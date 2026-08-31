import 'dotenv/config';
import express from "express";
import helmet from "helmet";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import { securityMiddleware } from "./middleware/securityMiddleware.js";
import { authMiddleware, requireRole } from "./middleware/authMiddleware.js";
import prisma from "./config/prisma.js";
import { resetFeatures } from "./core/monitor.js";

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not set. Add it to your .env file before starting the server.");
}

// Enhance API security with standard HTTP headers
app.use(helmet());

// Configure Cross-Origin Resource Sharing (CORS) for frontend communication
app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-device-id']
}));

// Parse incoming JSON payloads
app.use(express.json());

// Global Request Logger: Tracks incoming traffic at the entry point
app.use((req, res, next) => {
    console.log(`\n[TRAFFIC DETECTED] Request received on endpoint: ${req.path}`);
    next();
});

// Absolute path to the public/ directory, resolved from this file's own
// location rather than the bare relative string 'public'. A relative
// path is resolved against the process's current working directory at
// launch time, not against where server.js actually lives - if the
// server is ever started from a different cwd, that can silently point
// static serving somewhere else entirely (worst case, the project root,
// exposing server.js, prisma/, core/, and middleware/). An absolute path
// removes that whole class of risk regardless of how or from where the
// process is launched.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, 'public');

// GET /: explicit route for the site root, registered before the static
// middleware below so it always wins for this exact path - the Student
// Login Portal is never left to chance, an index-option default, or
// (if that file were ever briefly missing) any implicit fallback.
app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// GET /admin: dedicated entry point for the separate Admin Portal, so
// administrators have a clean, memorable URL instead of needing to know
// the exact admin_login.html filename. Intentionally unauthenticated -
// like every other login page, viewing the form itself requires no
// token; only the API calls it makes are gated by auth/security
// middleware.
app.get('/admin', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'admin_login.html'));
});

// Serve the remaining static frontend assets (CSS, JS, and other pages
// like signup.html) from public/ ONLY - never the project root.
// index: false explicitly disables express.static's own directory-index
// behavior. With the two explicit routes above already covering '/' and
// '/admin', static serving has no need to auto-resolve a bare directory
// to a file, and turning that off outright means there is no code path
// left anywhere in this file that could ever produce a directory
// listing for any path.
app.use(express.static(PUBLIC_DIR, { index: false }));

// Formats a Date exactly like the old TO_CHAR(log_time, 'YYYY-MM-DD HH12:MI:SS AM')
function formatLogTime(date) {
    const pad = (n) => String(n).padStart(2, '0');
    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    let hours = date.getHours();
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12 || 12;
    const minutes = pad(date.getMinutes());
    const seconds = pad(date.getSeconds());
    return `${year}-${month}-${day} ${pad(hours)}:${minutes}:${seconds} ${ampm}`;
}

// POST /api/login: Authenticate users and log security events
app.post("/api/login", securityMiddleware, async (req, res) => {
    const { email, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress || '127.0.0.1';
    const deviceId = req.headers["x-device-id"] || req.ip;

    try {
        const user = await prisma.user.findUnique({ where: { email } });
        const passwordMatches = user ? await bcrypt.compare(password, user.passwordHash) : false;

        if (passwordMatches) {
            resetFeatures(deviceId);

            const tokenTtlMs = 60 * 60 * 1000; // 1h - must match the JWT expiresIn below
            const token = jwt.sign(
                { email: user.email, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            // Persists the Session row middleware/authMiddleware.js looks
            // up on every authenticated request. Without this, that
            // token would verify forever (or until its natural 1h
            // expiry) with no way to revoke it early - this is the other
            // half of what makes "Force Logout" from the admin
            // dashboard's Blocked Devices panel actually work. upsert,
            // not create: an identical JWT (same payload + same
            // issued-at second) is vanishingly unlikely but not
            // impossible, and this must never be the reason a login
            // fails.
            try {
                await prisma.session.upsert({
                    where: { sessionToken: token },
                    update: { userId: user.id, expiresAt: new Date(Date.now() + tokenTtlMs) },
                    create: { userId: user.id, sessionToken: token, expiresAt: new Date(Date.now() + tokenTtlMs) }
                });
            } catch (sessionErr) {
                console.error("Session creation failed on login:", sessionErr.message);
                return res.status(500).json({ success: false, message: "Could not establish a secure session. Please try again." });
            }

            try {
                await Promise.all([
                    prisma.loginAttempt.create({
                        data: { userEmail: email, userId: user.id, ipAddress, status: 'SUCCESS' }
                    }),
                    prisma.behaviorLog.create({
                        data: { userEmail: email, userId: user.id, eventType: 'LOGIN_SUCCESS', description: 'User logged in successfully.' }
                    })
                ]);
            } catch (logErr) {
                console.error("Audit log write failed on successful login:", logErr.message);
            }

            res.json({ success: true, message: "Login successful!", role: user.role, token });
        } else {
            try {
                await Promise.all([
                    prisma.loginAttempt.create({
                        data: { userEmail: email, userId: user?.id ?? null, ipAddress, status: 'FAILED' }
                    }),
                    prisma.behaviorLog.create({
                        data: { userEmail: email, userId: user?.id ?? null, eventType: 'LOGIN_FAILED', description: 'Invalid password attempted.' }
                    })
                ]);
             } catch (logErr) {
                console.error("Audit log write failed on failed login:", logErr.message);
            }

            res.status(401).json({ success: false, message: "Invalid email or password." });
        }
    } catch (err) {
        console.error("Database query error:", err);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

// GET /api/admin/logs: Fetch recent security logs for the Admin Monitoring Dashboard
app.get("/api/admin/logs", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    try {
        const logs = await prisma.behaviorLog.findMany({
            orderBy: { logTime: 'desc' },
            take: 50
        });

        const formattedLogs = logs.map(log => ({
            id: log.id,
            user_email: log.userEmail,
            event_type: log.eventType,
            description: log.description,
            formatted_time: formatLogTime(log.logTime)
        }));

        res.json({ success: true, logs: formattedLogs });
    } catch (err) {
        console.error("Dashboard DB Error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch logs." });
    }
});

// GET /api/admin/scores: Recent WEVA anomaly scores, for the live chart
// on the admin dashboard (public/admin_dashboard.js polls this every
// ~1.5s). Deliberately NOT wrapped in securityMiddleware, unlike every
// other admin route: this endpoint is polled far more frequently than a
// normal user action, and running it through the scoring pipeline would
// (a) write 3 new audit rows on every single poll just to observe the
// dashboard, and worse, (b) feed the very chart it powers with noise
// from its own polling requests - a self-referential loop where looking
// at the data changes the data. Reading your own system's recent scores
// isn't itself a security-relevant action; it only needs to be
// authenticated as an admin, not behaviorally scored.
app.get("/api/admin/scores", authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const recent = await prisma.anomalyScore.findMany({
            orderBy: { calculatedAt: 'desc' },
            take: 40
        });

        // Reverse to chronological order (oldest -> newest) so the
        // frontend can plot left-to-right without re-sorting, and coerce
        // the Prisma Decimal `score` field to a plain number - Decimal
        // serializes to a string by default, which a canvas chart can't
        // do arithmetic on directly.
        const scores = recent.reverse().map(s => ({
            id: s.id,
            userEmail: s.userEmail,
            score: Number(s.score),
            riskLevel: s.riskLevel,
            calculatedAt: s.calculatedAt
        }));

        res.json({ success: true, scores });
    } catch (err) {
        console.error("Anomaly score fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch anomaly scores." });
    }
});

// GET /api/admin/blocked-devices: currently-blocked entries from
// core/mitigation.js's persistent ipTracking store, for the admin
// dashboard's Blocked Devices panel. Same reasoning as
// /api/admin/scores above for skipping securityMiddleware - a
// read-only status view of the mitigation layer shouldn't itself feed
// the mitigation layer.
app.get("/api/admin/blocked-devices", authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const devices = await prisma.ipTracking.findMany({
            where: { isBlocked: true, blockedUntil: { gt: new Date() } },
            orderBy: { blockedUntil: 'desc' }
        });
        res.json({ success: true, devices });
    } catch (err) {
        console.error("Blocked devices fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch blocked devices." });
    }
});

// POST /api/admin/blocked-devices/unblock: lifts a WEVA-imposed block
// early, and best-effort revokes the session of whichever user this
// device was most recently seen acting as. This IS a security-relevant
// mutation (unlike the read above), so it runs the full chain,
// including securityMiddleware.
//
// SE NOTE on the correlation: ipTracking has no direct relationship to
// a specific user - it's device/IP-scoped, not user-scoped, since a
// device can earn a block purely from repeated failed login attempts
// before any session ever existed. So "which session (if any) does
// this button revoke" is answered by looking up the most recent
// BehaviorLog entry mentioning this exact device - the same audit
// trail Priority #3's explainable-score work already writes
// (`Device ${deviceId} triggered ...`, see
// middleware/securityMiddleware.js) - and reading its userId back out.
// This is a best-effort correlation via existing audit data, not a
// hard foreign key; documented here rather than silently assumed.
app.post("/api/admin/blocked-devices/unblock", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { identifier } = req.body || {};
    if (!identifier) {
        return res.status(400).json({ success: false, message: "identifier is required." });
    }

    try {
        await prisma.ipTracking.updateMany({
            where: { ipAddress: identifier },
            data: { isBlocked: false, blockedUntil: null }
        });

        const recentActivity = await prisma.behaviorLog.findFirst({
            where: { description: { contains: `Device ${identifier} ` } },
            orderBy: { logTime: 'desc' }
        });

        let sessionsRevoked = 0;
        if (recentActivity?.userId) {
            const deleted = await prisma.session.deleteMany({ where: { userId: recentActivity.userId } });
            sessionsRevoked = deleted.count;
        }

        res.json({
            success: true,
            message: sessionsRevoked > 0
                ? `Device unblocked and ${sessionsRevoked} active session(s) revoked.`
                : "Device unblocked. No associated active session was found to revoke."
        });
    } catch (err) {
        console.error("Unblock/revoke error:", err);
        res.status(500).json({ success: false, message: "Cannot unblock device." });
    }
});

// GET /api/admin/backup: exports every table this schema currently
// models into one downloadable JSON snapshot - a real, working
// Disaster Recovery / Data Integrity feature for the admin dashboard's
// "Backup PostgreSQL DB" button, distinct from the placeholder
// POST /api/settings/backup route further down (that one stands in for
// a future pg_dump-based, database-engine-level backup and is
// deliberately left untouched; this is an application-level export -
// human-readable JSON of the actual rows, not a binary DB dump).
//
// DATA INTEGRITY NOTE: students, subjects, and grades are NOT included
// below because they don't exist as persisted records - schema.prisma
// has no Student/Subject/Grade model yet. Everything shown for those on
// the dashboard today is static placeholder markup (see the
// POST /api/students and /api/subjects placeholder routes above and
// their own "no Student model exists yet" comments), not database rows.
// They're still listed here as empty, clearly-labeled arrays rather
// than silently omitted or faked with mock data, so the exported shape
// is forward-compatible once those models are added, without a backup
// ever implying data exists that doesn't.
//
// Two fields are deliberately excluded for security reasons that have
// nothing to do with what's technically possible to export:
//   - User.passwordHash: a downloadable file in an admin's Downloads
//     folder is a worse place for bcrypt hashes to live than the
//     database itself. select: {} pulls everything else.
//   - the Session table entirely: it holds live bearer tokens (see
//     POST /api/login's prisma.session.upsert and
//     middleware/authMiddleware.js). A "backup" containing valid,
//     unexpired auth tokens would itself be a security liability, and
//     sessions are transient auth state, not data worth recovering.
app.get("/api/admin/backup", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    try {
        const [users, loginAttempts, anomalyScores, securityActions, behaviorLogs, ipTracking] = await Promise.all([
            prisma.user.findMany({ select: { id: true, email: true, role: true, createdAt: true } }),
            prisma.loginAttempt.findMany(),
            prisma.anomalyScore.findMany(),
            prisma.securityAction.findMany(),
            prisma.behaviorLog.findMany(),
            prisma.ipTracking.findMany()
        ]);

        res.json({
            success: true,
            generatedAt: new Date().toISOString(),
            generatedBy: req.user.email,
            students: [],
            subjects: [],
            grades: [],
            users,
            loginAttempts,
            anomalyScores,
            securityActions,
            behaviorLogs,
            ipTracking
        });
    } catch (err) {
        console.error("Database backup export error:", err);
        res.status(500).json({ success: false, message: "Backup export failed." });
    }
});

// =====================================================================
// INTERNAL ADMIN DASHBOARD ACTIONS
// =====================================================================
// Real, persisted CRUD against the Student/Subject/Grade models added
// to prisma/schema.prisma (pushed live via `npx prisma db push`) - this
// section used to be entirely placeholder handlers with a TODO in each
// body; that TODO is now resolved everywhere below.
//
// Every route below runs the same chain, in this specific order:
//
//   authMiddleware -> requireRole('admin') -> securityMiddleware -> handler
//
// authMiddleware MUST run first: it is what decodes the JWT and sets
// req.user = { email, role }. securityMiddleware then reads
// req.user.email/role to attribute every anomaly score, security action,
// and behavior log entry it writes (via its existing Promise.allSettled
// block, left completely untouched) to the specific admin performing the
// action. If the order were reversed, req.user would not exist yet when
// securityMiddleware runs, and every audit entry would fall back to
// "unauthenticated" instead of naming the admin. requireRole('admin')
// mirrors the existing GET /api/admin/logs route above, since these are
// all admin-only dashboard actions. The two GET (list) routes skip
// securityMiddleware, matching /api/admin/scores and
// /api/admin/blocked-devices above: they're read-only data loads the
// dashboard fires on every section-open, not sensitive mutations.

// GET /api/students: list all students, for the Student Records table.
app.get("/api/students", authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const students = await prisma.student.findMany({ orderBy: { studentId: 'asc' } });
        res.json({ success: true, students });
    } catch (err) {
        console.error("Students fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch students." });
    }
});

// POST /api/students: Add New Student
app.post("/api/students", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { studentId, fullName, department, program, yearLevel, status } = req.body || {};

    if (!studentId || !fullName) {
        return res.status(400).json({ success: false, message: "studentId and fullName are required." });
    }

    try {
        const student = await prisma.student.create({
            data: { studentId, fullName, department, program, yearLevel, status: status || 'ENROLLED' }
        });
        res.status(201).json({ success: true, message: `Student ${studentId} created.`, student, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2002') {
            return res.status(409).json({ success: false, message: `Student ID ${studentId} already exists.` });
        }
        console.error("Student creation error:", err);
        res.status(500).json({ success: false, message: "Could not create student." });
    }
});

// PUT /api/students/:id: Edit Student - :id is the human-readable
// studentId (e.g. "A23-00001"), not the numeric primary key, matching
// how public/admin_dashboard.js has always tracked rows (row.dataset.id).
// studentId itself is intentionally NOT updatable here (the frontend
// modal makes that field read-only in edit mode) - it's the stable
// lookup key this route, and every row in the UI, is keyed by.
app.put("/api/students/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;
    const { fullName, department, program, yearLevel, status } = req.body || {};

    try {
        const student = await prisma.student.update({
            where: { studentId: id },
            data: { fullName, department, program, yearLevel, status }
        });
        res.json({ success: true, message: `Student ${id} updated.`, student, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            return res.status(404).json({ success: false, message: `Student ${id} not found.` });
        }
        console.error("Student update error:", err);
        res.status(500).json({ success: false, message: "Could not update student." });
    }
});

// DELETE /api/students/:id: Remove Student
app.delete("/api/students/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;

    try {
        await prisma.student.delete({ where: { studentId: id } });
        res.json({ success: true, message: `Student ${id} removed.`, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            return res.status(404).json({ success: false, message: `Student ${id} not found.` });
        }
        if (err.code === 'P2003') {
            return res.status(409).json({ success: false, message: `Cannot remove ${id}: this student still has grade records.` });
        }
        console.error("Student deletion error:", err);
        res.status(500).json({ success: false, message: "Could not remove student." });
    }
});

// ---------------------------------------------------------------------
// SUBJECT MANAGEMENT
// ---------------------------------------------------------------------
// Mirrors the Student Records routes above exactly - same middleware
// chain, same reasoning. Backs the Subject Catalog table on the admin
// dashboard.
// ---------------------------------------------------------------------

// GET /api/subjects: list all subjects, for the Subject Catalog table.
app.get("/api/subjects", authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const subjects = await prisma.subject.findMany({ orderBy: { subjectCode: 'asc' } });
        res.json({ success: true, subjects });
    } catch (err) {
        console.error("Subjects fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch subjects." });
    }
});

// POST /api/subjects: Add Subject
app.post("/api/subjects", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { subjectCode, subjectTitle, units, department } = req.body || {};

    if (!subjectCode || !subjectTitle) {
        return res.status(400).json({ success: false, message: "subjectCode and subjectTitle are required." });
    }

    try {
        const subject = await prisma.subject.create({
            data: { subjectCode, subjectTitle, units: units ? Number(units) : undefined, department }
        });
        res.status(201).json({ success: true, message: `Subject ${subjectCode} created.`, subject, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2002') {
            return res.status(409).json({ success: false, message: `Subject code ${subjectCode} already exists.` });
        }
        console.error("Subject creation error:", err);
        res.status(500).json({ success: false, message: "Could not create subject." });
    }
});

// PUT /api/subjects/:id: Edit Subject - :id is subjectCode (e.g. "SE301"),
// same reasoning as students above.
app.put("/api/subjects/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;
    const { subjectTitle, units, department } = req.body || {};

    try {
        const subject = await prisma.subject.update({
            where: { subjectCode: id },
            data: { subjectTitle, units: units ? Number(units) : undefined, department }
        });
        res.json({ success: true, message: `Subject ${id} updated.`, subject, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            return res.status(404).json({ success: false, message: `Subject ${id} not found.` });
        }
        console.error("Subject update error:", err);
        res.status(500).json({ success: false, message: "Could not update subject." });
    }
});

// DELETE /api/subjects/:id: Remove Subject
app.delete("/api/subjects/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;

    try {
        await prisma.subject.delete({ where: { subjectCode: id } });
        res.json({ success: true, message: `Subject ${id} removed.`, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            return res.status(404).json({ success: false, message: `Subject ${id} not found.` });
        }
        if (err.code === 'P2003') {
            return res.status(409).json({ success: false, message: `Cannot remove ${id}: this subject still has grade records.` });
        }
        console.error("Subject deletion error:", err);
        res.status(500).json({ success: false, message: "Could not remove subject." });
    }
});

// ---------------------------------------------------------------------
// GRADE RECORDS (basic CRUD - not yet wired to any dashboard UI)
// ---------------------------------------------------------------------
// The "Modern UI Modals" work this task also covers only specified
// Add/Edit Student, Add/Edit Subject, and Create Admin - no Grade modal
// was in scope, so these routes exist and work but have no frontend
// caller yet. A natural next step, not done here without being asked.
// ---------------------------------------------------------------------

app.get("/api/grades", authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const grades = await prisma.grade.findMany({
            include: { student: true, subject: true },
            orderBy: { updatedAt: 'desc' }
        });
        res.json({ success: true, grades });
    } catch (err) {
        console.error("Grades fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch grades." });
    }
});

app.post("/api/grades", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { studentId, subjectCode, term, grade, remarks } = req.body || {};
    if (!studentId || !subjectCode) {
        return res.status(400).json({ success: false, message: "studentId and subjectCode are required." });
    }

    try {
        const student = await prisma.student.findUnique({ where: { studentId } });
        const subject = await prisma.subject.findUnique({ where: { subjectCode } });
        if (!student) return res.status(404).json({ success: false, message: `Student ${studentId} not found.` });
        if (!subject) return res.status(404).json({ success: false, message: `Subject ${subjectCode} not found.` });

        const created = await prisma.grade.create({
            data: { studentId: student.id, subjectId: subject.id, term, grade, remarks }
        });
        res.status(201).json({ success: true, message: `Grade recorded for ${studentId} in ${subjectCode}.`, grade: created });
    } catch (err) {
        if (err.code === 'P2002') {
            return res.status(409).json({ success: false, message: "A grade for this student, subject, and term already exists." });
        }
        console.error("Grade creation error:", err);
        res.status(500).json({ success: false, message: "Could not record grade." });
    }
});

app.put("/api/grades/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;
    const { grade, remarks } = req.body || {};

    try {
        const updated = await prisma.grade.update({
            where: { id: Number(id) },
            data: { grade, remarks }
        });
        res.json({ success: true, message: `Grade ${id} updated.`, grade: updated });
    } catch (err) {
        if (err.code === 'P2025') {
            return res.status(404).json({ success: false, message: `Grade ${id} not found.` });
        }
        console.error("Grade update error:", err);
        res.status(500).json({ success: false, message: "Could not update grade." });
    }
});

app.delete("/api/grades/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;

    try {
        await prisma.grade.delete({ where: { id: Number(id) } });
        res.json({ success: true, message: `Grade ${id} removed.` });
    } catch (err) {
        if (err.code === 'P2025') {
            return res.status(404).json({ success: false, message: `Grade ${id} not found.` });
        }
        console.error("Grade deletion error:", err);
        res.status(500).json({ success: false, message: "Could not remove grade." });
    }
});

// POST /api/admin/accounts: Create New Admin Account. This is the
// route "User Roles Management" -> "Create New Admin Account" opens a
// modal for on the dashboard. Weighted at the maximum 4x tier in
// core/scorer.js - minting a new admin is arguably higher-stakes than
// any single-record mutation elsewhere in this file, since it's a
// standing capability grant, not a data change.
app.post("/api/admin/accounts", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "email and password are required." });
    }
    if (password.length < 8) {
        return res.status(400).json({ success: false, message: "Password must be at least 8 characters." });
    }

    try {
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) {
            return res.status(409).json({ success: false, message: `An account with email ${email} already exists.` });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const newAdmin = await prisma.user.create({ data: { email, passwordHash, role: 'admin' } });

        res.status(201).json({
            success: true,
            message: `Admin account created for ${email}.`,
            admin: { id: newAdmin.id, email: newAdmin.email, role: newAdmin.role },
            createdBy: req.user.email
        });
    } catch (err) {
        console.error("Admin account creation error:", err);
        res.status(500).json({ success: false, message: "Could not create admin account." });
    }
});

// POST /api/settings/backup: Backup PostgreSQL DB (placeholder)
app.post("/api/settings/backup", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    // TODO: shell out to `pg_dump` (or a managed backup provider) here.
    // Deliberately not implemented yet - this route's job right now is to
    // prove the auth + security pipeline gates this highly sensitive
    // action correctly (see endpointWeights in core/scorer.js, where this
    // path carries the maximum 4x sensitivity weight).
    res.json({
        success: true,
        message: "Database backup request received (placeholder - no backup has actually been triggered).",
        requestedBy: req.user.email
    });
});

// POST /api/settings/restore: Restore PostgreSQL DB from Backup (placeholder)
app.post("/api/settings/restore", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    // TODO: implement actual restore logic (e.g. `pg_restore` against a
    // selected backup file/snapshot) here. Deliberately not implemented
    // yet, for the same reason as /api/settings/backup above - this
    // route's job right now is to prove the auth + security pipeline
    // gates it correctly. Worth calling out explicitly: a bad restore can
    // silently overwrite live production data, which arguably makes it
    // even higher-stakes than backup in a real implementation (e.g. it
    // should probably require a second confirmation step or a second
    // admin's approval) even though both share the same maximum 4x
    // sensitivity weight in core/scorer.js today.
    res.json({
        success: true,
        message: "Database restore request received (placeholder - no restore has actually been triggered).",
        requestedBy: req.user.email
    });
});

// =====================================================================
// DEMO / DEFENSE-DAY TOOLING
// =====================================================================

// POST /api/demo/ping: harmless, no-op endpoint that exists purely to be
// scored. It routes through the exact same authMiddleware ->
// requireRole('admin') -> securityMiddleware chain as every real action
// above, so a burst of requests here exercises the genuine WEVA pipeline
// end to end (core/monitor.js -> core/profiler.js -> core/scorer.js ->
// core/decisionEngine.js -> core/mitigation.js). This is what the
// dashboard's "Simulate Attack" button calls to make the live anomaly
// chart visibly climb through LOG/THROTTLE/BLOCK on demand, without
// needing to actually hammer a real destructive endpoint to prove the
// algorithm works.
app.post("/api/demo/ping", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    res.json({ success: true, message: "Ping scored by the WEVA pipeline." });
});

// Initialize the server instance
app.listen(PORT, () => {
  console.log("--------------------------------------------------");
  console.log(`🟢 SYSTEM ONLINE: Server is actively listening on Port ${PORT}`);
  console.log("--------------------------------------------------");
});