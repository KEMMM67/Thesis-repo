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
import { securityConfig } from "./config/securityConfig.js";
import { PrismaAuditSink, PrismaIpTrackingStore, PrismaIdentityResolver } from "./adapters/prisma/index.js";
import { createWeva } from "./core/weva.js";
import { summarizeGrades } from "./utils/gradeSummary.js";
import { streamDatabaseExport } from "./utils/databaseExport.js";

const app = express();
const PORT = process.env.PORT || 3000;

// Which X-Forwarded-For entries to believe when resolving req.ip. Render's
// edge terminates TLS and forwards each request to this process through its
// own private network, and every proxy on the way appends the address it
// received the request from. Without trusting those proxies, req.ip would be
// a Render proxy's address for every request - collapsing WEVA's per-IP
// scoring (core/ipAttempts.js), the campus-intranet IP whitelist
// (middleware/ipWhitelistMiddleware.js), and the login-attempt audit trail
// onto one shared "IP" for every user.
//
// On Render a request passes through Cloudflare, then Render's load balancer,
// then an internal proxy, and arrives with a header shaped like:
//
//   X-Forwarded-For: 81.97.145.24, 172.71.195.123, 10.226.90.65
//                    client        Cloudflare edge  Render internal
//
// with the socket itself coming from that internal proxy. Trusting 3 hops
// walks back past the socket, 10.226.90.65 and 172.71.195.123 and stops on the
// client. Both earlier values were wrong, and each failure showed up in the
// logs: trusting 1 hop gave the Render-internal address (10.26.132.94) for
// everyone; trusting private ranges stopped on the Cloudflare edge address,
// which changes from request to request, so WEVA's IP layer never saw a bot's
// attempts land on one "IP" and a rotating-device bot got 15 password checks
// before its first throttle instead of 4.
//
// Spoof-proof, unlike `true`: Cloudflare and Render append to
// X-Forwarded-For rather than resetting it, so anything a client writes into
// the header sits to the LEFT of the entry Cloudflare recorded and is never
// reached. If Render ever adds or removes a hop, this number must follow -
// check that the [SECURITY] log's IP matches https://api.ipify.org. Harmless
// locally: a direct connection sends no X-Forwarded-For, so req.ip is the
// loopback client.
app.set('trust proxy', 3);

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

/**
 * Serves WEVA's production scoring function to the browser, for the
 * Algorithm Comparative Analysis page (public/compare.html). That page
 * imports this exact file, so its "WEVA (Ours)" simulation computes every
 * score with the same code the server runs, and can never drift into a
 * different formula than the one the manuscript describes.
 *
 * core/scorer.js is safe to serve: it is a pure function with no imports,
 * I/O or secrets. Publishing a detection formula is standard practice
 * (Kerckhoffs's principle) - security rests on the server enforcing it,
 * not on an attacker not knowing it.
 */
app.get('/weva/scorer.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'core', 'scorer.js'));
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

/**
 * Reads a search box's text from a query parameter. Anything other than a
 * single string (e.g. `?q=a&q=b`, which arrives as an array) counts as no
 * search, and the length is capped: no student ID, name or subject title
 * is anywhere near 100 characters.
 *
 * @param {*} value - Raw `req.query` value.
 * @returns {string} Trimmed search text, or '' for no search.
 */
function searchParam(value) {
    return typeof value === 'string' ? value.trim().slice(0, 100) : '';
}

/**
 * Escapes SQL LIKE's wildcards (and its escape character) so `text` is
 * matched literally. On Postgres, Prisma runs case-insensitive `contains`
 * and `equals` filters as ILIKE and passes the text through unescaped, so
 * without this a search for "%" or "_" matched every student, and a lookup
 * of "A23-0000_" found A23-00001. Typed into a search box during a
 * security review, that looks exactly like an injection. It is not one -
 * the text always travels as a bound parameter, never as SQL - but results
 * should still be exactly what was asked for.
 *
 * @param {string} text
 * @returns {string}
 */
function escapeLike(text) {
    return text.replace(/[\\%_]/g, '\\$&');
}

/**
 * Reads an integer query parameter, falling back when it is missing or not
 * a number, and clamping it to [min, max].
 *
 * @param {*} value - Raw `req.query` value.
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function intParam(value, fallback, min, max) {
    const parsed = Number.parseInt(value, 10);
    return Number.isNaN(parsed) ? fallback : Math.min(Math.max(parsed, min), max);
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
 * @route GET /api/admin/stats
 * @access Admin
 * @description Live counts behind the Dashboard's stat cards, polled by
 * public/admin_dashboard.js every few seconds. Not routed through
 * securityMiddleware, for the same reason as /api/admin/scores above.
 *
 * `blockVerdicts` counts requests WEVA itself scored at BLOCK, from the
 * security_actions audit table. It is a lower bound on requests refused:
 * a request from an already-blocked device is refused too, but is audited
 * under whatever its own score was (see core/mitigation.js).
 * `devicesBlockedNow` is the same query as the Blocked Devices panel.
 */
app.get("/api/admin/stats", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const now = new Date();
        const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const [studentsEnrolled, studentsTotal, subjects, gradeRecords, blockVerdicts, blockVerdicts24h, devicesBlockedNow] = await Promise.all([
            prisma.student.count({ where: { status: 'ENROLLED' } }),
            prisma.student.count(),
            prisma.subject.count(),
            prisma.grade.count(),
            prisma.securityAction.count({ where: { actionTaken: 'BLOCK' } }),
            prisma.securityAction.count({ where: { actionTaken: 'BLOCK', actionTime: { gte: dayAgo } } }),
            prisma.ipTracking.count({ where: { isBlocked: true, blockedUntil: { gt: now } } })
        ]);

        res.json({
            success: true,
            stats: {
                studentsEnrolled,
                studentsTotal,
                subjects,
                gradeRecords,
                blockVerdicts,
                blockVerdicts24h,
                devicesBlockedNow,
                lockoutSeconds: Math.round(securityConfig.mitigation.temporaryBlockMs / 1000)
            }
        });
    } catch (err) {
        console.error("Dashboard stats fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch dashboard stats." });
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
 * @description Streams a JSON snapshot of every table - students,
 * subjects, grades, users and the full WEVA audit trail - as a file
 * download (the dashboard's "Export JSON Snapshot" button). See
 * utils/databaseExport.js for how it stays within a fixed memory budget,
 * why every table comes from one REPEATABLE READ transaction, and what is
 * kept out of the file (password hashes, OTP codes, session tokens,
 * plaintext grades).
 *
 * This is an application-level export, not the engine-level backup:
 * restores run through AWS RDS automated snapshots (point-in-time
 * recovery), outside this web console.
 *
 * Once the first bytes are sent, a failure can no longer become a JSON
 * error response. The connection is aborted instead, so the browser
 * reports a failed download rather than saving a truncated file that
 * looks complete.
 */
app.get("/api/admin/backup", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const generatedAt = new Date();
    const filename = `sis_snapshot_${generatedAt.toISOString().replace(/[:.]/g, '-')}.json`;
    res.set({
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Cache-Control': 'no-store'
    });

    try {
        await streamDatabaseExport(prisma, res, { generatedBy: req.user.email, generatedAt });
        res.end();
    } catch (err) {
        console.error("Database snapshot export error:", err);
        if (!res.headersSent) {
            res.removeHeader('Content-Disposition');
            return res.status(500).json({ success: false, message: "Snapshot export failed." });
        }
        res.destroy();
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

        const { grades, stats } = summarizeGrades(gradeRows);

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
            stats,
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
 * @description One page of the Student Records table, optionally narrowed
 * by the table's search box.
 *
 * Query parameters:
 *   - q: case-insensitive text matched against student ID, full name,
 *     program and department.
 *   - limit: rows per page, 1-200 (default 100).
 *   - offset: rows to skip (default 0).
 *
 * Paged because the table holds 15,000+ students: returning every row cost
 * megabytes of JSON and seconds of rendering on each visit. `total` counts
 * every row matching `q`, not just this page, so the table can report
 * "1-100 of 15,010".
 */
app.get("/api/students", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    const q = searchParam(req.query.q);
    const limit = intParam(req.query.limit, 100, 1, 200);
    // Prisma's skip is a 32-bit integer.
    const offset = intParam(req.query.offset, 0, 0, 2 ** 31 - 1);
    const where = q
        ? {
            OR: ['studentId', 'fullName', 'program', 'department'].map(field => ({
                [field]: { contains: escapeLike(q), mode: 'insensitive' }
            }))
        }
        : {};

    try {
        const [students, total] = await Promise.all([
            prisma.student.findMany({ where, orderBy: { studentId: 'asc' }, skip: offset, take: limit }),
            prisma.student.count({ where })
        ]);
        res.json({ success: true, students, total, offset, limit });
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
 * @description Lists subjects for the Subject Catalog table. An optional
 * `q` narrows the list to subjects whose code, title or department
 * contains it (case-insensitive). Not paged: a subject catalog is small.
 */
app.get("/api/subjects", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    const q = searchParam(req.query.q);
    const where = q
        ? {
            OR: ['subjectCode', 'subjectTitle', 'department'].map(field => ({
                [field]: { contains: escapeLike(q), mode: 'insensitive' }
            }))
        }
        : {};

    try {
        const subjects = await prisma.subject.findMany({ where, orderBy: { subjectCode: 'asc' } });
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
// GRADE RECORDS (read by the Grade Management lookup; create, update and
// delete are implemented but not yet wired to a dashboard UI)
// ---------------------------------------------------------------------

/**
 * @route GET /api/students/:id/grades
 * @access Admin
 * @description One student's grade report for the Grade Management
 * lookup: their record, their grades, and the same units/GWA/standing
 * summary they see on their own dashboard (see summarizeGrades()). `:id`
 * is the human-readable studentId, matched case-insensitively so
 * "ca22-000001" finds CA22-000001.
 *
 * Grades are queried through prisma.grade rather than as a nested include
 * on the student: the field-encryption extension
 * (adapters/prisma/fieldEncryption.js) decrypts the rows of the model a
 * query is made on, so grades fetched as a nested relation of a student
 * would come back as ciphertext.
 */
app.get("/api/students/:id/grades", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    const id = req.params.id.trim();

    try {
        const student = await prisma.student.findFirst({
            where: { studentId: { equals: escapeLike(id), mode: 'insensitive' } }
        });
        if (!student) {
            return res.status(404).json({ success: false, message: `No student found with ID ${id}.` });
        }

        const gradeRows = await prisma.grade.findMany({
            where: { studentId: student.id },
            include: { subject: true },
            orderBy: { subject: { subjectCode: 'asc' } }
        });

        res.json({
            success: true,
            student: {
                studentId: student.studentId,
                fullName: student.fullName,
                department: student.department,
                program: student.program,
                yearLevel: student.yearLevel,
                status: student.status
            },
            ...summarizeGrades(gradeRows)
        });
    } catch (err) {
        console.error("Student grade lookup error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch this student's grades." });
    }
});

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
