import 'dotenv/config';
import express from "express";
import helmet from "helmet";
import cors from "cors";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";
import https from "https";
import fs from "fs";
import { authMiddleware, requireRole } from "./middleware/authMiddleware.js";
import prisma from "./config/prisma.js";
import { PrismaAuditSink, PrismaIpTrackingStore, PrismaIdentityResolver } from "./adapters/prisma/index.js";
import { createWeva } from "./core/weva.js";

const app = express();
const PORT = process.env.PORT || 3000;

// Trusts exactly one hop of X-Forwarded-For (Render's own edge proxy, which
// terminates TLS and forwards every request to this process over its
// internal network - see the HTTPS setup notes below). Without this,
// Express's req.ip resolves to that proxy's own address for every request
// once deployed, not the real client - collapsing WEVA's per-device/IP
// behavioral profiling (core/monitor.js), the campus-intranet IP whitelist
// (middleware/ipWhitelistMiddleware.js), and controllers/authController.js's
// login-attempt logging onto one identical "IP" for every user. Set to 1
// (not `true`, which would trust the whole X-Forwarded-For chain -
// spoofable by the client) because Render sits exactly one proxy hop in
// front of this app; a different number of hops in a future deployment
// topology would need this value updated to match. Harmless locally: a
// direct, non-proxied connection never sends X-Forwarded-For, so req.ip
// still resolves to the real local client either way.
app.set('trust proxy', 1);

if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not set. Add it to your .env file before starting the server.");
}

app.use(helmet());

app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-device-id']
}));

app.use(express.json());

app.use((req, res, next) => {
    console.log(`\n[TRAFFIC DETECTED] Request received on endpoint: ${req.path}`);
    next();
});

// Resolved from this file's own location, not the process's working
// directory, so static serving cannot be pointed at an unintended
// directory (e.g. the project root, exposing server.js and core/) if the
// server is ever launched from a different cwd.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, 'public');

/** Serves the Student Login Portal at the site root. */
app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Unauthenticated by design: viewing a login form, like any login page,
// requires no token - only the API calls it makes are gated by
// auth/security middleware.
/** Serves the Admin Portal entry point. */
app.get('/admin', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'admin_login.html'));
});

// index: false disables express.static's directory-index behavior; the
// two explicit routes above already cover '/' and '/admin', so no path in
// this file can produce a directory listing.
app.use(express.static(PUBLIC_DIR, { index: false }));

/**
 * Formats a Date as `YYYY-MM-DD HH12:MI:SS AM`, matching the legacy
 * `TO_CHAR(log_time, 'YYYY-MM-DD HH12:MI:SS AM')` output format expected
 * by the admin dashboard's log views.
 *
 * @param {Date} date - Date to format.
 * @returns {string} Formatted timestamp.
 */
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

// ---------------------------------------------------------------------
// WEVA WIRING
// ---------------------------------------------------------------------
// The only place in this app that touches WEVA's internals directly: it
// constructs the Prisma-backed adapters (see core/ports.js for the
// AuditSink/IpTrackingStore/IdentityResolver interfaces they implement,
// adapters/prisma/ for these implementations) and hands them to
// createWeva() (core/weva.js) - the framework's single public entry
// point, returning every piece of middleware already wired. Nothing
// below this block, and nothing inside core/mitigation.js,
// middleware/securityMiddleware.js, or middleware/ipWhitelistMiddleware.js,
// imports Prisma. A deployment on a different database swaps these three
// constructor calls for a different adapter implementing the same
// interface; nothing else in the security pipeline, or in this file,
// changes.
const weva = createWeva({
    auditSink: new PrismaAuditSink(prisma),
    ipTrackingStore: new PrismaIpTrackingStore(prisma),
    identityResolver: new PrismaIdentityResolver(prisma)
});

const securityMiddleware = weva.securityMiddleware();
const ipWhitelistMiddleware = weva.ipWhitelistMiddleware();

// POST /api/login lives in controllers/authController.js + routes/authRoutes.js
// (mounted below), not inline here - see those files for the WEVA-protected
// authentication flow (bcrypt compare -> JWT -> session -> audit log ->
// best-effort login-alert email).
app.use("/api", weva.authRoutes());

/**
 * @route GET /api/admin/logs
 * @access Admin
 * @description Returns the 50 most recent behavior log entries for the
 * Admin Monitoring Dashboard.
 */
app.get("/api/admin/logs", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route GET /api/admin/scores
 * @access Admin
 * @description Returns recent WEVA anomaly scores for the dashboard's live
 * chart, polled by public/admin_dashboard.js at short intervals.
 *
 * Deliberately not routed through securityMiddleware, unlike other admin
 * routes: at polling frequency it would write audit rows on every poll and
 * feed the very chart it powers with noise from its own requests. Reading
 * recent scores is not itself security-relevant; it only needs admin
 * authentication.
 */
app.get("/api/admin/scores", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const recent = await prisma.anomalyScore.findMany({
            orderBy: { calculatedAt: 'desc' },
            take: 40
        });

        // Reversed to chronological order so the frontend can plot
        // left-to-right without re-sorting; `score` is coerced from Prisma's
        // Decimal (which serializes to a string) to a plain number.
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

/**
 * @route GET /api/admin/blocked-devices
 * @access Admin
 * @description Returns currently-blocked devices from the persistent
 * ipTracking store (core/mitigation.js) for the Blocked Devices panel. Not
 * routed through securityMiddleware for the same reason as
 * /api/admin/scores above: a read-only view of the mitigation layer should
 * not itself feed the mitigation layer.
 */
app.get("/api/admin/blocked-devices", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
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

/**
 * @route POST /api/admin/blocked-devices/unblock
 * @access Admin
 * @description Lifts a WEVA-imposed block early and best-effort revokes
 * the session of the user most recently associated with the device. A
 * security-relevant mutation, so it runs the full middleware chain
 * including securityMiddleware.
 *
 * ipTracking is device/IP-scoped, not user-scoped - a device can be
 * blocked purely from failed login attempts before any session exists.
 * The session to revoke is therefore resolved by looking up the most
 * recent BehaviorLog entry naming this device
 * (`Device ${deviceId} triggered ...`, written by
 * middleware/securityMiddleware.js) and reading its userId. This is a
 * best-effort correlation via existing audit data, not a hard foreign
 * key relationship.
 */
app.post("/api/admin/blocked-devices/unblock", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route GET /api/admin/backup
 * @access Admin
 * @description Exports every modeled table as a downloadable JSON
 * snapshot - an application-level export of the actual rows, distinct
 * from the placeholder database-engine-level backup at
 * POST /api/settings/backup.
 *
 * students/subjects/grades are included as empty arrays rather than
 * omitted, keeping the exported shape forward-compatible; at the time of
 * writing they are represented as dashboard-only placeholder data with no
 * corresponding persisted rows in some deployments of this schema.
 *
 * `User.passwordHash` and the entire Session table are deliberately
 * excluded: a downloadable file is a worse place for password hashes to
 * live than the database itself, and a backup containing live, unexpired
 * bearer tokens would itself be a security liability.
 */
app.get("/api/admin/backup", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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
// ADMIN DASHBOARD RESOURCE ROUTES: Students, Subjects, Grades
// =====================================================================
// Every mutating route below runs the same chain, in this order:
//
//   ipWhitelistMiddleware -> authMiddleware -> requireRole('admin') -> securityMiddleware -> handler
//
// ipWhitelistMiddleware runs first, ahead of even authMiddleware: it is a
// network-layer check (middleware/ipWhitelistMiddleware.js, simulating a
// campus-intranet-only admin portal), and a disallowed origin should be
// rejected before spending any compute on JWT verification, let alone
// behavioral scoring. authMiddleware runs next, since it decodes the JWT
// and sets req.user; securityMiddleware depends on req.user to attribute
// the anomaly score, security action, and behavior log entries it writes
// to the specific admin performing the action. List (GET) routes omit
// securityMiddleware, consistent with /api/admin/scores and
// /api/admin/blocked-devices above: they are read-only loads fired on
// every section-open, not sensitive mutations.

/**
 * @route GET /api/students/me
 * @access Student
 * @description Returns the logged-in student's own profile and grades for
 * the student dashboard (public/student_dashboard.js), replacing the
 * static per-student content that used to be hardcoded directly into
 * student_dashboard.html.
 *
 * The student is resolved from req.user.email (set by authMiddleware
 * after verifying the JWT) via Student.userId, never from any
 * client-supplied id - accepting e.g. a ?studentId= query parameter here
 * would trade the broken-access-control bug this endpoint exists to fix
 * for an IDOR (Insecure Direct Object Reference), letting one student
 * read another's grades by simply changing the parameter. This handler
 * can only ever return the record belonging to whoever the JWT says is
 * making the request.
 *
 * Schedule, billing, and clearance have no backing persistence model yet
 * (see the Student/Grade models in prisma/schema.prisma) and are
 * returned as fixed placeholder values, clearly labeled as such below -
 * consistent with how GET /api/admin/backup above already treats
 * students/subjects/grades as forward-compatible placeholders. They are
 * served from here rather than left hardcoded in student_dashboard.html
 * so the entire dashboard, not just profile/grades, requires a valid,
 * authenticated request to view.
 */
app.get("/api/students/me", authMiddleware, requireRole('student'), async (req, res) => {
    try {
        const user = await prisma.user.findUnique({ where: { email: req.user.email } });
        const student = user ? await prisma.student.findUnique({ where: { userId: user.id } }) : null;

        if (!student) {
            return res.status(404).json({
                success: false,
                message: "No student record is linked to this account yet. Contact the registrar's office."
            });
        }

        const gradeRows = await prisma.grade.findMany({
            where: { studentId: student.id },
            include: { subject: true },
            orderBy: { updatedAt: 'desc' }
        });

        const grades = gradeRows.map(g => ({
            subjectCode: g.subject.subjectCode,
            subjectTitle: g.subject.subjectTitle,
            units: g.subject.units,
            term: g.term,
            grade: g.grade != null ? Number(g.grade) : null,
            remarks: g.remarks
        }));

        // Enrolled units and GWA are computed from the real grade rows above
        // rather than stored as separate fields, so they can never drift out
        // of sync with the grades that back them. This seed data uses the
        // Philippine 1.0 (highest) - 5.0 (lowest) grading scale, so the
        // average is taken directly (no inversion), and 3.00 is the
        // conventional passing ceiling for "Good Standing".
        const numericGrades = grades.map(g => g.grade).filter(g => g != null);
        const enrolledUnits = grades.reduce((sum, g) => sum + (g.units || 0), 0);
        const gwa = numericGrades.length
            ? Math.round((numericGrades.reduce((sum, g) => sum + g, 0) / numericGrades.length) * 100) / 100
            : null;
        const academicStanding = gwa == null ? 'No Grades Yet' : (gwa <= 3.00 ? 'Good Standing' : 'On Probation');

        // Shared display label for the schedule/grades/billing sections
        // below - derived from the grade rows' own term rather than
        // duplicated per section, so it can never disagree with the grades
        // it is describing.
        const currentTerm = grades.length ? grades[0].term : 'No Term on File';

        res.json({
            success: true,
            currentTerm,
            profile: {
                studentId: student.studentId,
                fullName: student.fullName,
                department: student.department,
                program: student.program,
                yearLevel: student.yearLevel,
                status: student.status,
                email: user.email
            },
            stats: { enrolledUnits, gwa, academicStanding },
            grades,
            // ---- Placeholder sections (see the route description above) ----
            schedule: [
                { subjectCode: 'SE301', subjectTitle: 'Software Engineering 1', units: 3, schedule: 'Mon / Wed · 08:00 AM - 09:30 AM', room: 'CCMS Lab 3', instructor: 'Prof. Cruz' },
                { subjectCode: 'IAS301', subjectTitle: 'Information Assurance & Security', units: 3, schedule: 'Tue / Thu · 01:00 PM - 02:30 PM', room: 'CCMS Lec Rm 2', instructor: 'Prof. Santos' },
                { subjectCode: 'HCI101', subjectTitle: 'Human-Computer Interaction', units: 3, schedule: 'Friday · 03:30 PM - 06:30 PM', room: 'CCMS Lab 1', instructor: 'Prof. Mendoza' }
            ],
            billing: {
                balanceDue: 0,
                status: 'Paid in Full',
                fees: [
                    { type: 'Tuition Fee', amount: 15000 },
                    { type: 'Miscellaneous Fee', amount: 2500 },
                    { type: 'Laboratory Fee', amount: 1000 }
                ],
                payments: [
                    { date: '2026-03-01', orNumber: 'OR-00192', amount: 18500, description: 'Full Tuition Payment' }
                ]
            },
            clearance: [
                { requirement: 'Library Clearance', office: 'MSEUF Main Library', status: 'Cleared' },
                { requirement: 'Guidance Clearance', office: 'Guidance Office', status: 'Cleared' },
                { requirement: 'Departmental Clearance', office: "CCMS Dean's Office", status: 'Cleared' },
                { requirement: 'Accounting Clearance', office: 'Cashier / Accounting Office', status: 'Cleared' },
                { requirement: 'Student Affairs Clearance', office: 'Office of Student Affairs', status: 'Cleared' }
            ]
        });
    } catch (err) {
        console.error("Student self-service fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch your dashboard data." });
    }
});

/**
 * @route GET /api/students
 * @access Admin
 * @description Lists all students for the Student Records table.
 */
app.get("/api/students", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const students = await prisma.student.findMany({ orderBy: { studentId: 'asc' } });
        res.json({ success: true, students });
    } catch (err) {
        console.error("Students fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch students." });
    }
});

/**
 * @route POST /api/students
 * @access Admin
 * @description Creates a new student record.
 */
app.post("/api/students", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route PUT /api/students/:id
 * @access Admin
 * @description Updates an existing student record. `:id` is the
 * human-readable studentId (e.g. "A23-00001"), matching how
 * public/admin_dashboard.js tracks rows; studentId itself is not
 * updatable, as it is the stable lookup key the UI keys rows by.
 */
app.put("/api/students/:id", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route DELETE /api/students/:id
 * @access Admin
 * @description Removes a student record.
 */
app.delete("/api/students/:id", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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
// SUBJECT MANAGEMENT (mirrors Student Records above: same middleware
// chain, same reasoning; backs the Subject Catalog table)
// ---------------------------------------------------------------------

/**
 * @route GET /api/subjects
 * @access Admin
 * @description Lists all subjects for the Subject Catalog table.
 */
app.get("/api/subjects", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const subjects = await prisma.subject.findMany({ orderBy: { subjectCode: 'asc' } });
        res.json({ success: true, subjects });
    } catch (err) {
        console.error("Subjects fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch subjects." });
    }
});

/**
 * @route POST /api/subjects
 * @access Admin
 * @description Creates a new subject record.
 */
app.post("/api/subjects", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route PUT /api/subjects/:id
 * @access Admin
 * @description Updates an existing subject record. `:id` is the
 * subjectCode (e.g. "SE301").
 */
app.put("/api/subjects/:id", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route DELETE /api/subjects/:id
 * @access Admin
 * @description Removes a subject record.
 */
app.delete("/api/subjects/:id", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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
// GRADE RECORDS (CRUD implemented; not yet wired to a dashboard UI)
// ---------------------------------------------------------------------

/**
 * @route GET /api/grades
 * @access Admin
 * @description Lists all grade records with their related student and subject.
 */
app.get("/api/grades", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
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

/**
 * @route POST /api/grades
 * @access Admin
 * @description Records a new grade for a student in a subject.
 */
app.post("/api/grades", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route PUT /api/grades/:id
 * @access Admin
 * @description Updates an existing grade record.
 */
app.put("/api/grades/:id", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route DELETE /api/grades/:id
 * @access Admin
 * @description Removes a grade record.
 */
app.delete("/api/grades/:id", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route POST /api/admin/accounts
 * @access Admin
 * @description Creates a new administrator account. Weighted at the
 * maximum 4x sensitivity tier in core/scorer.js, since minting a new
 * admin is a standing capability grant rather than a single data change.
 */
app.post("/api/admin/accounts", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
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

/**
 * @route POST /api/settings/backup
 * @access Admin
 * @description Placeholder for a database-engine-level backup (e.g. via
 * `pg_dump`). Not yet implemented; this route's current purpose is to
 * validate that the auth + security pipeline gates the action correctly
 * at its configured 4x sensitivity weight (core/scorer.js).
 */
app.post("/api/settings/backup", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    // TODO: shell out to `pg_dump` (or a managed backup provider).
    res.json({
        success: true,
        message: "Database backup request received (placeholder - no backup has actually been triggered).",
        requestedBy: req.user.email
    });
});

/**
 * @route POST /api/settings/restore
 * @access Admin
 * @description Placeholder for a database-engine-level restore (e.g. via
 * `pg_restore`). Not yet implemented, for the same reason as
 * /api/settings/backup above. A production implementation should require
 * additional confirmation, since a bad restore can silently overwrite
 * live data.
 */
app.post("/api/settings/restore", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    // TODO: implement restore (e.g. `pg_restore` against a selected snapshot).
    res.json({
        success: true,
        message: "Database restore request received (placeholder - no restore has actually been triggered).",
        requestedBy: req.user.email
    });
});

/**
 * @route POST /api/demo/ping
 * @access Admin
 * @description No-op endpoint routed through the full anomaly-detection
 * pipeline so a burst of requests can exercise it end to end without
 * hitting a real destructive endpoint. Backs the dashboard's
 * "Simulate Attack" control.
 */
app.post("/api/demo/ping", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    res.json({ success: true, message: "Ping scored by the WEVA pipeline." });
});

// ---------------------------------------------------------------------
// HTTP vs HTTPS LISTENER
// ---------------------------------------------------------------------
// ENABLE_HTTPS mirrors the same fail-open-to-simple, read-fresh-from-env
// pattern as ENABLE_IP_WHITELIST (middleware/ipWhitelistMiddleware.js):
// unset, or anything other than "true", keeps today's plain-HTTP dev
// workflow completely undisturbed - fs.readFileSync below never even runs
// in that mode, so a missing cert can't break normal day-to-day
// development. Only set it once certs/ holds a real mkcert-issued
// key/cert pair (see the Local HTTPS/TLS setup notes) for the live
// thesis-defense demo.
const ENABLE_HTTPS = (process.env.ENABLE_HTTPS || '').trim().toLowerCase() === 'true';

if (ENABLE_HTTPS) {
    const keyPath = process.env.TLS_KEY_PATH || path.join(__dirname, 'certs', 'localhost-key.pem');
    const certPath = process.env.TLS_CERT_PATH || path.join(__dirname, 'certs', 'localhost-cert.pem');

    let httpsOptions;
    try {
        httpsOptions = {
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath)
        };
    } catch (err) {
        throw new Error(
            `ENABLE_HTTPS is true but the TLS key/cert could not be read (${err.message}). ` +
            `Generate them with mkcert first - see the Local HTTPS/TLS setup notes - or set ` +
            `TLS_KEY_PATH/TLS_CERT_PATH to point at an existing pair.`
        );
    }

    https.createServer(httpsOptions, app).listen(PORT, () => {
        console.log("--------------------------------------------------");
        console.log(`🟢 SYSTEM ONLINE (HTTPS): Server is actively listening on https://localhost:${PORT}`);
        console.log("--------------------------------------------------");
    });
} else {
    app.listen(PORT, () => {
        console.log("--------------------------------------------------");
        console.log(`🟢 SYSTEM ONLINE: Server is actively listening on Port ${PORT}`);
        console.log("--------------------------------------------------");
    });
}
