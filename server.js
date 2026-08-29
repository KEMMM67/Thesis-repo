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

            const token = jwt.sign(
                { email: user.email, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

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

// =====================================================================
// INTERNAL ADMIN DASHBOARD ACTIONS (placeholder endpoints)
// =====================================================================
// The admin dashboard UI already has buttons for these actions (Add New
// Student, Edit, Remove, Backup, etc.) but the backend never exposed
// routes for them. These are intentionally PLACEHOLDER handlers: there
// is no dedicated Student model in prisma/schema.prisma yet (the student
// rows shown in the dashboard today are static markup), so rather than
// break the schema to fake persistence, each handler validates/
// acknowledges the request and demonstrates the full authenticated +
// monitored pipeline. Swap the TODO body of each handler for a real
// Prisma call once a Student model exists.
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
// "unauthenticated" instead of naming the admin - defeating the point of
// this task. requireRole('admin') mirrors the existing GET
// /api/admin/logs route above, since these are all admin-only dashboard
// actions.
// =====================================================================

// POST /api/students: Add New Student (placeholder - no Student model yet)
app.post("/api/students", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { studentId, fullName } = req.body || {};

    if (!studentId || !fullName) {
        return res.status(400).json({ success: false, message: "studentId and fullName are required." });
    }

    // TODO: once a Student model exists in prisma/schema.prisma, persist
    // the new record here (e.g. prisma.student.create({ data: {...} })).
    res.status(201).json({
        success: true,
        message: `Student ${studentId} received for enrollment (placeholder - not yet persisted).`,
        submittedBy: req.user.email
    });
});

// PUT /api/students/:id: Edit Student (placeholder - no Student model yet)
app.put("/api/students/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;

    // TODO: once a Student model exists, look it up and apply the update
    // here (e.g. prisma.student.update({ where: { id }, data: req.body })).
    res.json({
        success: true,
        message: `Update for student ${id} received (placeholder - not yet persisted).`,
        submittedBy: req.user.email
    });
});

// DELETE /api/students/:id: Remove Student (placeholder - no Student model yet)
app.delete("/api/students/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;

    // TODO: once a Student model exists, remove it here (e.g.
    // prisma.student.delete({ where: { id } })).
    res.json({
        success: true,
        message: `Removal of student ${id} received (placeholder - not yet persisted).`,
        submittedBy: req.user.email
    });
});

// ---------------------------------------------------------------------
// SUBJECT MANAGEMENT (placeholder endpoints)
// ---------------------------------------------------------------------
// Mirrors the Student Records routes above exactly - same middleware
// chain, same reasoning, same "no matching Prisma model yet" caveat.
// These back the Subject Catalog table (Edit / Remove buttons per row)
// on the admin dashboard.
// ---------------------------------------------------------------------

// POST /api/subjects: Add Subject (placeholder - no Subject model yet)
app.post("/api/subjects", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { subjectCode, subjectTitle } = req.body || {};

    if (!subjectCode || !subjectTitle) {
        return res.status(400).json({ success: false, message: "subjectCode and subjectTitle are required." });
    }

    // TODO: once a Subject model exists in prisma/schema.prisma, persist
    // the new record here (e.g. prisma.subject.create({ data: {...} })).
    res.status(201).json({
        success: true,
        message: `Subject ${subjectCode} received for the catalog (placeholder - not yet persisted).`,
        submittedBy: req.user.email
    });
});

// PUT /api/subjects/:id: Edit Subject (placeholder - no Subject model yet)
app.put("/api/subjects/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;

    // TODO: once a Subject model exists, look it up and apply the update
    // here (e.g. prisma.subject.update({ where: { id }, data: req.body })).
    res.json({
        success: true,
        message: `Update for subject ${id} received (placeholder - not yet persisted).`,
        submittedBy: req.user.email
    });
});

// DELETE /api/subjects/:id: Remove Subject (placeholder - no Subject model yet)
app.delete("/api/subjects/:id", authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;

    // TODO: once a Subject model exists, remove it here (e.g.
    // prisma.subject.delete({ where: { id } })).
    res.json({
        success: true,
        message: `Removal of subject ${id} received (placeholder - not yet persisted).`,
        submittedBy: req.user.email
    });
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

// Initialize the server instance
app.listen(PORT, () => {
  console.log("--------------------------------------------------");
  console.log(`🟢 SYSTEM ONLINE: Server is actively listening on Port ${PORT}`);
  console.log("--------------------------------------------------");
});