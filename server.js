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
import { apiNotFound, jsonErrorHandler } from "./middleware/errorHandlers.js";
import prisma from "./config/prisma.js";
import { securityConfig } from "./config/securityConfig.js";
import { resolveTrustProxy } from "./config/trustProxy.js";
import { describeDatabaseUrl } from "./config/databaseUrl.js";
import { PrismaAuditSink, PrismaIpTrackingStore, PrismaIdentityResolver } from "./adapters/prisma/index.js";
import { createWeva } from "./core/weva.js";
import { parseAccountKey, getClientIdentity } from "./middleware/clientIdentity.js";
import { readVerdict } from "./middleware/securityMiddleware.js";
import { summarizeGrades } from "./utils/gradeSummary.js";
import { GRADE_SCALE, parseGrade, parseShortText } from "./utils/gradeScale.js";
import { streamDatabaseExport } from "./utils/databaseExport.js";
import { withAudit, recordAudit, verifyAuditChain, readAuditDetail, diffFields } from "./utils/auditTrail.js";

const app = express();
const PORT = process.env.PORT || 3000;

// Which X-Forwarded-For entries to believe when resolving req.ip - the
// address WEVA's IP layer (core/ipAttempts.js), the campus-intranet IP
// whitelist (middleware/ipWhitelistMiddleware.js) and the login-attempt
// audit trail all rely on. It must match the deployment's proxy chain
// exactly: 3 hops on Render, none on a local or LAN server, or
// TRUST_PROXY_HOPS when set. This used to be a hard-coded 3, which let any
// client of a non-Render server forge its own IP. See config/trustProxy.js.
const trustProxy = resolveTrustProxy(process.env);
app.set('trust proxy', trustProxy.hops);
console.log(`[CONFIG] trust proxy: ${trustProxy.hops} hop(s) - ${trustProxy.source}`);

// The TLS and pool settings Prisma will use for RDS, read off DATABASE_URL's
// query parameters - never the URL itself, which holds the password. Warns
// on Render if sslmode=require or connection_limit is missing; see
// config/databaseUrl.js.
const database = describeDatabaseUrl(process.env);
console.log(`[CONFIG] database: ${database.summary}`);
database.warnings.forEach(warning => console.warn(`[CONFIG] WARNING: ${warning}`));

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

/** How long GET /healthz waits on the database before calling it unreachable. */
const HEALTH_DB_TIMEOUT_MS = 3000;

/**
 * @route GET /healthz
 * @access Public
 * @description Health check for Render (set as the service's Health Check
 * Path) and for the keep-warm pinger that stops the free instance from
 * spinning down during defense week. Answers 200 only if the database
 * answers a trivial `SELECT 1` too: a process that is up but cannot reach
 * RDS cannot serve a single page of real data, so it should not be
 * reported healthy - with this as Render's health check, a deploy whose
 * DATABASE_URL is wrong fails its check instead of going live.
 *
 * Deliberately outside every other layer: no auth, no IP whitelist, and
 * not scored by WEVA, so a ping every few minutes never writes audit rows
 * or feeds the dashboard's anomaly chart. It reveals nothing - a fixed
 * body, and no error detail (that goes to the server log only). It is
 * registered ahead of the traffic logger below so those pings do not
 * flood the console either.
 *
 * The timeout matters because a dead database does not fail fast: Prisma
 * waits up to its connect/pool timeouts first. A health check that hangs
 * looks the same as a server that hangs.
 */
app.get('/healthz', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    let timer;
    try {
        await Promise.race([
            prisma.$queryRaw`SELECT 1`,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error(`no answer within ${HEALTH_DB_TIMEOUT_MS} ms`)), HEALTH_DB_TIMEOUT_MS);
            })
        ]);
        res.json({ status: 'ok', database: 'ok' });
    } catch (err) {
        console.error('[HEALTH] Database check failed:', err.message);
        res.status(503).json({ status: 'error', database: 'unreachable' });
    } finally {
        clearTimeout(timer);
    }
});

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

/**
 * Reads a date-range filter from `from`/`to` query parameters: ISO 8601
 * instants, which the dashboard computes as the start and end of the chosen
 * days in the administrator's own time zone (the server's is UTC on
 * Render, so it cannot know where a "day" begins). A bound that is missing
 * or not a valid date is ignored.
 *
 * @param {*} from - Raw `req.query.from`.
 * @param {*} to - Raw `req.query.to`.
 * @returns {{gte?: Date, lte?: Date}|null} A Prisma DateTime filter, or null for no range.
 */
function dateRange(from, to) {
    const parse = (value) => {
        if (typeof value !== 'string' || value.length > 40) return null;
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? null : date;
    };
    const range = {};
    const start = parse(from);
    const end = parse(to);
    if (start) range.gte = start;
    if (end) range.lte = end;
    return start || end ? range : null;
}

// ---------------------------------------------------------------------
// AUDIT TRAIL HELPERS (see utils/auditTrail.js)
// ---------------------------------------------------------------------
// Every admin route that changes something records it in the audit trail:
// a change that reached the database is recorded atomically with it
// (withAudit), and an attempt the database refused or that failed - a 404,
// a 409, a 500 - is recorded on its own (auditFailure). Two kinds of
// request are left out on purpose: one rejected by input validation (400)
// before any record was looked up, since nothing was attempted, and one
// WEVA blocked, which never reached the handler. Both are still in the
// Security Events log, which records every scored request.

/** The fields the audit trail records for each kind of record - never passwords, hashes or tokens. */
const STUDENT_AUDIT_FIELDS = ['studentId', 'fullName', 'department', 'program', 'yearLevel', 'status'];
const SUBJECT_AUDIT_FIELDS = ['subjectCode', 'subjectTitle', 'units', 'department'];
const GRADE_AUDIT_FIELDS = ['term', 'grade', 'remarks'];

/** entityType values the Audit Trail can be filtered by - every kind of record auditEntry() is called with below. */
const AUDIT_ENTITY_TYPES = ['Student', 'Subject', 'Grade', 'AdminAccount', 'WevaBlock', 'Database'];

/**
 * The who/what/where of an audit entry. The administrator comes from the
 * verified JWT and its Session row (req.user/req.auth, set by
 * authMiddleware), and the IP and device ID are the same identities WEVA
 * scores (middleware/clientIdentity.js) - nothing here comes from the
 * request body.
 *
 * @param {import("express").Request} req
 * @param {string} action - e.g. "STUDENT_UPDATE".
 * @param {string} entityType - One of AUDIT_ENTITY_TYPES.
 * @param {*} entityId - The record's human-readable key; truncated to the column's 150 characters, since a failed lookup records whatever ID was requested.
 * @returns {object} The fields utils/auditTrail.js needs, minus outcome and detail.
 */
function auditEntry(req, action, entityType, entityId) {
    const { ip, deviceId } = getClientIdentity(req);
    return {
        actorUserId: req.auth?.userId ?? null,
        actorEmail: req.user.email,
        actorRole: req.user.role,
        action,
        entityType,
        entityId: String(entityId ?? '').slice(0, 150),
        ipAddress: ip,
        deviceId
    };
}

/**
 * Records an attempt that was refused or failed. Best-effort and never
 * throws - see utils/auditTrail.js#recordAudit.
 *
 * @param {object} entry - From auditEntry().
 * @param {number} statusCode - The status the administrator received.
 * @param {string} note - Why it did not go through.
 * @returns {Promise<void>}
 */
function auditFailure(entry, statusCode, note) {
    return recordAudit(prisma, { ...entry, outcome: 'FAILURE', statusCode, detail: { note } });
}

/**
 * Whether `err` is Postgres refusing to delete a row other rows still
 * reference - here, a student or subject that still has grades.
 *
 * The grade foreign keys are ON DELETE RESTRICT, which Postgres reports as
 * SQLSTATE 23001 (restrict_violation), not 23503 (foreign_key_violation).
 * Prisma maps only 23503 to its P2003 code; 23001 arrives as an unknown
 * request error with no code at all, carrying the SQLSTATE only in its
 * message. So the delete routes' P2003 checks never matched, and removing a
 * student with grades answered 500 instead of 409 (found when the audit
 * trail recorded that 500; reproduced on Prisma 6.19 with PostgreSQL 18).
 * Both forms are checked.
 *
 * @param {*} err
 * @returns {boolean}
 */
function isStillReferenced(err) {
    return err?.code === 'P2003' || /code: "23001"/.test(String(err?.message));
}

/**
 * A grade's audit key: its student, subject and term - the grade's own
 * natural key (prisma/schema.prisma: @@unique([studentId, subjectId, term])),
 * so the trail can be searched by student ID.
 *
 * @param {string} studentId - e.g. "A23-00001".
 * @param {string} subjectCode - e.g. "SE301".
 * @param {string|null} term
 * @returns {string} e.g. "A23-00001 · SE301 · 1st Sem 2025-2026".
 */
function gradeKey(studentId, subjectCode, term) {
    return [studentId, subjectCode, term].filter(Boolean).join(' · ');
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

/** The behavior_logs event types whose description carries a WEVA verdict (see readVerdict). */
const VERDICT_EVENT_TYPES = ['SECURITY_EVALUATION', 'NETWORK_ACCESS_DENIED'];
const VERDICTS = ['ALLOW', 'LOG', 'THROTTLE', 'BLOCK'];

/**
 * @route GET /api/admin/logs
 * @access Admin
 * @description One page of the Security Events log (behavior_logs),
 * newest first, for the dashboard's Security & Logs section.
 *
 * Query parameters, all optional:
 *   - type: one event type, e.g. SECURITY_EVALUATION or LOGIN_FAILED.
 *   - verdict: ALLOW, LOG, THROTTLE or BLOCK.
 *   - q: text matched against the account email and the description, which
 *     names the device, IP or account WEVA scored and the endpoint it hit.
 *   - from / to: ISO 8601 instants bounding the event time (see dateRange()).
 *   - limit: rows per page, 1-200 (default 50); offset: rows to skip.
 *
 * Each WEVA evaluation carries its `verdict` as its own field, read from
 * the one position the server writes it - so the dashboard colors a row by
 * that field, never by searching the description, part of which is the
 * client-chosen device ID (see middleware/securityMiddleware.js#readVerdict).
 * The verdict *filter* relies on the same fixed position: it matches
 * " triggered <VERDICT> ", which in a verdict-bearing description occurs
 * only right after the scored key - a key cannot contain a space, so
 * nothing in front of it can fake the sequence, and the trailing space
 * keeps LOG from matching LOGIN.
 *
 * Times are sent as ISO 8601 instants and formatted by the browser, in the
 * administrator's own time zone. They used to be formatted here, in the
 * server's - UTC on Render, so an attack blocked at 10:15 AM in Manila was
 * listed at 02:15 AM.
 */
app.get("/api/admin/logs", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const type = searchParam(req.query.type);
    const verdict = VERDICTS.includes(req.query.verdict) ? req.query.verdict : null;
    const q = searchParam(req.query.q);
    const logTime = dateRange(req.query.from, req.query.to);
    const limit = intParam(req.query.limit, 50, 1, 200);
    const offset = intParam(req.query.offset, 0, 0, 2 ** 31 - 1);

    const conditions = [];
    if (type) conditions.push({ eventType: type });
    if (verdict) conditions.push({ eventType: { in: VERDICT_EVENT_TYPES } }, { description: { contains: ` triggered ${verdict} ` } });
    if (q) {
        conditions.push({
            OR: ['userEmail', 'description'].map(field => ({ [field]: { contains: escapeLike(q), mode: 'insensitive' } }))
        });
    }
    if (logTime) conditions.push({ logTime });
    const where = conditions.length ? { AND: conditions } : {};

    try {
        const [logs, total] = await Promise.all([
            prisma.behaviorLog.findMany({ where, orderBy: [{ logTime: 'desc' }, { id: 'desc' }], skip: offset, take: limit }),
            prisma.behaviorLog.count({ where })
        ]);

        res.json({
            success: true,
            logs: logs.map(log => ({
                id: log.id,
                user_email: log.userEmail,
                event_type: log.eventType,
                verdict: readVerdict(log.description),
                description: log.description,
                logged_at: log.logTime.toISOString()
            })),
            total,
            offset,
            limit
        });
    } catch (err) {
        console.error("Dashboard DB Error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch logs." });
    }
});

/**
 * @route GET /api/admin/audit
 * @access Admin
 * @description One page of the administrative audit trail (audit_logs -
 * see utils/auditTrail.js), newest first.
 *
 * Query parameters, all optional:
 *   - entity: one of AUDIT_ENTITY_TYPES, e.g. Grade.
 *   - outcome: SUCCESS or FAILURE.
 *   - q: text matched against the administrator's email and the record's
 *     key - a student ID finds every change to that student and to their
 *     grades (a grade's key starts with its student ID; see gradeKey()).
 *   - from / to, limit, offset: as GET /api/admin/logs.
 *
 * Each entry's encrypted `detail` is decrypted for display. `detailReadable:
 * false` means the ciphertext failed AES-GCM authentication, i.e. it was
 * altered; the dashboard says so instead of showing an empty change list.
 * `hash` is the entry's seal, shown so a printed report records it.
 *
 * Scored by WEVA at 2x, like GET /api/admin/logs: it exposes the record of
 * every change made to the system.
 */
app.get("/api/admin/audit", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const entity = AUDIT_ENTITY_TYPES.includes(req.query.entity) ? req.query.entity : null;
    const outcome = ['SUCCESS', 'FAILURE'].includes(req.query.outcome) ? req.query.outcome : null;
    const q = searchParam(req.query.q);
    const occurredAt = dateRange(req.query.from, req.query.to);
    const limit = intParam(req.query.limit, 50, 1, 200);
    const offset = intParam(req.query.offset, 0, 0, 2 ** 31 - 1);

    const conditions = [];
    if (entity) conditions.push({ entityType: entity });
    if (outcome) conditions.push({ outcome });
    if (q) {
        conditions.push({
            OR: ['actorEmail', 'entityId'].map(field => ({ [field]: { contains: escapeLike(q), mode: 'insensitive' } }))
        });
    }
    if (occurredAt) conditions.push({ occurredAt });
    const where = conditions.length ? { AND: conditions } : {};

    try {
        const [rows, total] = await Promise.all([
            prisma.auditLog.findMany({ where, orderBy: { id: 'desc' }, skip: offset, take: limit }),
            prisma.auditLog.count({ where })
        ]);

        res.json({
            success: true,
            entries: rows.map(row => {
                const { detail, readable } = readAuditDetail(row.detail);
                return {
                    id: row.id,
                    occurredAt: row.occurredAt.toISOString(),
                    actorEmail: row.actorEmail,
                    actorRole: row.actorRole,
                    action: row.action,
                    entityType: row.entityType,
                    entityId: row.entityId,
                    outcome: row.outcome,
                    statusCode: row.statusCode,
                    ipAddress: row.ipAddress,
                    deviceId: row.deviceId,
                    detail,
                    detailReadable: readable,
                    hash: row.hash
                };
            }),
            total,
            offset,
            limit
        });
    } catch (err) {
        console.error("Audit trail fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch the audit trail." });
    }
});

/**
 * @route GET /api/admin/audit/verify
 * @access Admin
 * @description Recomputes the seal of every audit entry, oldest first,
 * and reports whether the chain is intact - or the first entry where it
 * breaks, and why (utils/auditTrail.js#verifyAuditChain). Read-only; safe
 * to run at any time. Scored by WEVA at 2x like the trail itself.
 */
app.get("/api/admin/audit/verify", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    try {
        const result = await verifyAuditChain(prisma);
        res.json({ success: true, ...result, verifiedAt: new Date().toISOString() });
    } catch (err) {
        console.error("Audit chain verification error:", err);
        res.status(500).json({ success: false, message: "Could not verify the audit trail." });
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
 * @description Returns currently-blocked identities from the persistent
 * ipTracking store (core/mitigation.js) for the Blocked Devices panel:
 * devices, IPs, and - since WEVA also scores the signed-in account
 * (middleware/securityMiddleware.js) - whole accounts, stored as
 * "user:<id>". Each account block gets `accountEmail` so the panel can name
 * the account instead of showing a bare id. Not routed through
 * securityMiddleware for the same reason as /api/admin/scores above: a
 * read-only view of the mitigation layer should not itself feed the
 * mitigation layer.
 */
app.get("/api/admin/blocked-devices", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const devices = await prisma.ipTracking.findMany({
            where: { isBlocked: true, blockedUntil: { gt: new Date() } },
            orderBy: { blockedUntil: 'desc' }
        });

        const accountIds = devices.map(d => parseAccountKey(d.ipAddress)).filter(id => id != null);
        const accounts = accountIds.length
            ? await prisma.user.findMany({ where: { id: { in: accountIds } }, select: { id: true, email: true } })
            : [];
        const emailById = new Map(accounts.map(a => [a.id, a.email]));

        res.json({
            success: true,
            devices: devices.map(d => {
                const accountId = parseAccountKey(d.ipAddress);
                return accountId == null ? d : { ...d, accountEmail: emailById.get(accountId) ?? `user #${accountId}` };
            })
        });
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
 * @description Lifts a WEVA-imposed block early and revokes the sessions
 * that go with it. A security-relevant mutation, so it runs the full
 * middleware chain including securityMiddleware.
 *
 * Which sessions depends on what was blocked:
 *
 *   - An account ("user:<id>", blocked by WEVA's account layer - see
 *     middleware/securityMiddleware.js): every session of that account.
 *     The account layer only decides when an account's traffic is spread
 *     across devices - the stolen-token pattern - so lifting the block
 *     without ending those sessions would hand a working token back.
 *   - A device or IP: ipTracking is device/IP-scoped, not user-scoped - a
 *     device can be blocked purely from failed login attempts before any
 *     session exists. The session to revoke is therefore resolved by
 *     looking up the most recent BehaviorLog entry naming this device
 *     (`Device ${deviceId} triggered ...`, written by
 *     middleware/securityMiddleware.js) and reading its userId. This is a
 *     best-effort correlation via existing audit data, not a hard foreign
 *     key relationship.
 *
 * `identifier` must be a string. It is used as a column value, and anything
 * else - e.g. {"not": ""} - would reach Prisma as a query operator and
 * unblock every row at once.
 */
app.post("/api/admin/blocked-devices/unblock", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { identifier } = req.body || {};
    if (typeof identifier !== 'string' || !identifier) {
        return res.status(400).json({ success: false, message: "identifier must be a non-empty string." });
    }

    const audit = auditEntry(req, 'BLOCK_LIFT', 'WevaBlock', identifier);
    const accountId = parseAccountKey(identifier);
    const unblocked = accountId == null ? 'Device' : 'Account';

    try {
        // Lifting the block, revoking the sessions and the audit entry
        // commit together: a block can never be lifted without a record of
        // who lifted it.
        const sessionsRevoked = await withAudit(prisma, audit, async (tx) => {
            const lifted = await tx.ipTracking.updateMany({
                where: { ipAddress: identifier },
                data: { isBlocked: false, blockedUntil: null }
            });

            let userIdToRevoke = accountId;
            if (userIdToRevoke == null) {
                const recentActivity = await tx.behaviorLog.findFirst({
                    where: { description: { contains: `Device ${identifier} ` } },
                    orderBy: { logTime: 'desc' }
                });
                userIdToRevoke = recentActivity?.userId ?? null;
            }

            let revoked = 0;
            if (userIdToRevoke != null) {
                const deleted = await tx.session.deleteMany({ where: { userId: userIdToRevoke } });
                revoked = deleted.count;
            }

            const note = lifted.count === 0
                ? `${unblocked} had no block on record; ${revoked} active session(s) revoked.`
                : `${unblocked} block lifted early; ${revoked} active session(s) revoked.`;
            return { result: revoked, detail: { note } };
        });

        res.json({
            success: true,
            message: sessionsRevoked > 0
                ? `${unblocked} unblocked and ${sessionsRevoked} active session(s) revoked.`
                : `${unblocked} unblocked. No associated active session was found to revoke.`
        });
    } catch (err) {
        console.error("Unblock/revoke error:", err);
        await auditFailure(audit, 500, 'The block could not be lifted.');
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
 *
 * Every export is recorded in the audit trail (DATA_EXPORT) once it has
 * finished or failed - a copy of every student record leaving the system
 * is exactly what an auditor asks about first. It is recorded on its own,
 * not atomically: the export only reads, so there is nothing to roll back.
 */
app.get("/api/admin/backup", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const generatedAt = new Date();
    const filename = `sis_snapshot_${generatedAt.toISOString().replace(/[:.]/g, '-')}.json`;
    const audit = auditEntry(req, 'DATA_EXPORT', 'Database', filename);
    res.set({
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Cache-Control': 'no-store'
    });

    try {
        await streamDatabaseExport(prisma, res, { generatedBy: req.user.email, generatedAt });
        res.end();
        await recordAudit(prisma, { ...audit, outcome: 'SUCCESS', statusCode: 200, detail: { note: 'Full JSON snapshot downloaded.' } });
    } catch (err) {
        console.error("Database snapshot export error:", err);
        await auditFailure(audit, 500, 'The snapshot export failed before it finished; no complete file was delivered.');
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

    const audit = auditEntry(req, 'STUDENT_CREATE', 'Student', studentId);
    try {
        const student = await withAudit(prisma, { ...audit, statusCode: 201 }, async (tx) => {
            const created = await tx.student.create({
                data: { studentId, fullName, department, program, yearLevel, status: status || 'ENROLLED' }
            });
            return { result: created, detail: { changes: diffFields(null, created, STUDENT_AUDIT_FIELDS) } };
        });
        res.status(201).json({ success: true, message: `Student ${studentId} created.`, student, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2002') {
            await auditFailure(audit, 409, 'A student with this ID already exists.');
            return res.status(409).json({ success: false, message: `Student ID ${studentId} already exists.` });
        }
        console.error("Student creation error:", err);
        await auditFailure(audit, 500, 'The student could not be created.');
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

    const audit = auditEntry(req, 'STUDENT_UPDATE', 'Student', id);
    try {
        const student = await withAudit(prisma, audit, async (tx) => {
            const before = await tx.student.findUnique({ where: { studentId: id } });
            const after = await tx.student.update({
                where: { studentId: id },
                data: { fullName, department, program, yearLevel, status }
            });
            return { result: after, detail: { changes: diffFields(before, after, STUDENT_AUDIT_FIELDS) } };
        });
        res.json({ success: true, message: `Student ${id} updated.`, student, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            await auditFailure(audit, 404, 'No student with this ID exists.');
            return res.status(404).json({ success: false, message: `Student ${id} not found.` });
        }
        console.error("Student update error:", err);
        await auditFailure(audit, 500, 'The student could not be updated.');
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

    const audit = auditEntry(req, 'STUDENT_DELETE', 'Student', id);
    try {
        // The removed record is kept in the entry, field by field - after
        // this, the audit trail is the only place it still exists.
        await withAudit(prisma, audit, async (tx) => {
            const removed = await tx.student.delete({ where: { studentId: id } });
            return { result: removed, detail: { changes: diffFields(removed, null, STUDENT_AUDIT_FIELDS) } };
        });
        res.json({ success: true, message: `Student ${id} removed.`, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            await auditFailure(audit, 404, 'No student with this ID exists.');
            return res.status(404).json({ success: false, message: `Student ${id} not found.` });
        }
        if (isStillReferenced(err)) {
            await auditFailure(audit, 409, 'Refused: the student still has grade records.');
            return res.status(409).json({ success: false, message: `Cannot remove ${id}: this student still has grade records.` });
        }
        console.error("Student deletion error:", err);
        await auditFailure(audit, 500, 'The student could not be removed.');
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

    const audit = auditEntry(req, 'SUBJECT_CREATE', 'Subject', subjectCode);
    try {
        const subject = await withAudit(prisma, { ...audit, statusCode: 201 }, async (tx) => {
            const created = await tx.subject.create({
                data: { subjectCode, subjectTitle, units: units ? Number(units) : undefined, department }
            });
            return { result: created, detail: { changes: diffFields(null, created, SUBJECT_AUDIT_FIELDS) } };
        });
        res.status(201).json({ success: true, message: `Subject ${subjectCode} created.`, subject, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2002') {
            await auditFailure(audit, 409, 'A subject with this code already exists.');
            return res.status(409).json({ success: false, message: `Subject code ${subjectCode} already exists.` });
        }
        console.error("Subject creation error:", err);
        await auditFailure(audit, 500, 'The subject could not be created.');
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

    const audit = auditEntry(req, 'SUBJECT_UPDATE', 'Subject', id);
    try {
        const subject = await withAudit(prisma, audit, async (tx) => {
            const before = await tx.subject.findUnique({ where: { subjectCode: id } });
            const after = await tx.subject.update({
                where: { subjectCode: id },
                data: { subjectTitle, units: units ? Number(units) : undefined, department }
            });
            return { result: after, detail: { changes: diffFields(before, after, SUBJECT_AUDIT_FIELDS) } };
        });
        res.json({ success: true, message: `Subject ${id} updated.`, subject, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            await auditFailure(audit, 404, 'No subject with this code exists.');
            return res.status(404).json({ success: false, message: `Subject ${id} not found.` });
        }
        console.error("Subject update error:", err);
        await auditFailure(audit, 500, 'The subject could not be updated.');
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

    const audit = auditEntry(req, 'SUBJECT_DELETE', 'Subject', id);
    try {
        await withAudit(prisma, audit, async (tx) => {
            const removed = await tx.subject.delete({ where: { subjectCode: id } });
            return { result: removed, detail: { changes: diffFields(removed, null, SUBJECT_AUDIT_FIELDS) } };
        });
        res.json({ success: true, message: `Subject ${id} removed.`, submittedBy: req.user.email });
    } catch (err) {
        if (err.code === 'P2025') {
            await auditFailure(audit, 404, 'No subject with this code exists.');
            return res.status(404).json({ success: false, message: `Subject ${id} not found.` });
        }
        if (isStillReferenced(err)) {
            await auditFailure(audit, 409, 'Refused: the subject still has grade records.');
            return res.status(409).json({ success: false, message: `Cannot remove ${id}: this subject still has grade records.` });
        }
        console.error("Subject deletion error:", err);
        await auditFailure(audit, 500, 'The subject could not be removed.');
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

/** Message for a grade that is not on the scale (see utils/gradeScale.js). */
const INVALID_GRADE_MESSAGE = `grade must be one of ${GRADE_SCALE.join(', ')}, or null for an incomplete/dropped subject.`;

/**
 * Reads a numeric record id from a route parameter.
 *
 * @param {string} value - e.g. req.params.id
 * @returns {number|null} The id, or null if it is not a positive integer.
 */
function recordId(value) {
    const id = Number(value);
    return Number.isInteger(id) && id > 0 ? id : null;
}

/**
 * @route POST /api/grades
 * @access Admin
 * @description Records a new grade for a student in a subject. The grade is
 * checked against the grading scale before it is encrypted and stored -
 * the encrypted column can no longer reject a bad value itself (see
 * utils/gradeScale.js).
 */
app.post("/api/grades", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { studentId, subjectCode } = req.body || {};
    if (typeof studentId !== 'string' || typeof subjectCode !== 'string' || !studentId || !subjectCode) {
        return res.status(400).json({ success: false, message: "studentId and subjectCode are required." });
    }
    const grade = parseGrade(req.body.grade);
    if (!grade.ok) return res.status(400).json({ success: false, message: INVALID_GRADE_MESSAGE });
    const term = parseShortText(req.body.term);
    const remarks = parseShortText(req.body.remarks);
    if (!term.ok || !remarks.ok) {
        return res.status(400).json({ success: false, message: "term and remarks must be text of at most 50 characters." });
    }

    const audit = auditEntry(req, 'GRADE_CREATE', 'Grade', gradeKey(studentId, subjectCode, term.value));
    try {
        const student = await prisma.student.findUnique({ where: { studentId } });
        const subject = await prisma.subject.findUnique({ where: { subjectCode } });
        if (!student) {
            await auditFailure(audit, 404, 'No student with this ID exists.');
            return res.status(404).json({ success: false, message: `Student ${studentId} not found.` });
        }
        if (!subject) {
            await auditFailure(audit, 404, 'No subject with this code exists.');
            return res.status(404).json({ success: false, message: `Subject ${subjectCode} not found.` });
        }

        const created = await withAudit(prisma, { ...audit, statusCode: 201 }, async (tx) => {
            const row = await tx.grade.create({
                data: { studentId: student.id, subjectId: subject.id, term: term.value, grade: grade.value, remarks: remarks.value }
            });
            return {
                result: row,
                entityId: gradeKey(student.studentId, subject.subjectCode, row.term),
                detail: { changes: diffFields(null, row, GRADE_AUDIT_FIELDS) }
            };
        });
        res.status(201).json({ success: true, message: `Grade recorded for ${studentId} in ${subjectCode}.`, grade: created });
    } catch (err) {
        if (err.code === 'P2002') {
            await auditFailure(audit, 409, 'A grade for this student, subject and term already exists.');
            return res.status(409).json({ success: false, message: "A grade for this student, subject, and term already exists." });
        }
        console.error("Grade creation error:", err);
        await auditFailure(audit, 500, 'The grade could not be recorded.');
        res.status(500).json({ success: false, message: "Could not record grade." });
    }
});

/**
 * @route PUT /api/grades/:id
 * @access Admin
 * @description Updates an existing grade record's grade and/or remarks.
 * Fields left out of the body are left unchanged; the grade is checked
 * against the grading scale as in POST /api/grades.
 */
app.put("/api/grades/:id", ipWhitelistMiddleware, authMiddleware, requireRole('admin'), securityMiddleware, async (req, res) => {
    const { id } = req.params;
    const gradeId = recordId(id);
    if (gradeId == null) return res.status(400).json({ success: false, message: "Grade id must be a positive integer." });
    const grade = parseGrade(req.body?.grade);
    if (!grade.ok) return res.status(400).json({ success: false, message: INVALID_GRADE_MESSAGE });
    const remarks = parseShortText(req.body?.remarks);
    if (!remarks.ok) return res.status(400).json({ success: false, message: "remarks must be text of at most 50 characters." });

    const audit = auditEntry(req, 'GRADE_UPDATE', 'Grade', `Grade #${gradeId}`);
    try {
        // The case an SIS audit trail exists for: a grade changed after the
        // fact. The entry keeps the old and new grade - encrypted, like the
        // grade itself (see utils/auditTrail.js).
        const updated = await withAudit(prisma, audit, async (tx) => {
            const before = await tx.grade.findUnique({ where: { id: gradeId }, include: { student: true, subject: true } });
            const after = await tx.grade.update({
                where: { id: gradeId },
                data: { grade: grade.value, remarks: remarks.value }
            });
            return {
                result: after,
                entityId: gradeKey(before.student.studentId, before.subject.subjectCode, before.term),
                detail: { changes: diffFields(before, after, GRADE_AUDIT_FIELDS) }
            };
        });
        res.json({ success: true, message: `Grade ${id} updated.`, grade: updated });
    } catch (err) {
        if (err.code === 'P2025') {
            await auditFailure(audit, 404, 'No grade with this id exists.');
            return res.status(404).json({ success: false, message: `Grade ${id} not found.` });
        }
        console.error("Grade update error:", err);
        await auditFailure(audit, 500, 'The grade could not be updated.');
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
    const gradeId = recordId(id);
    if (gradeId == null) return res.status(400).json({ success: false, message: "Grade id must be a positive integer." });

    const audit = auditEntry(req, 'GRADE_DELETE', 'Grade', `Grade #${gradeId}`);
    try {
        await withAudit(prisma, audit, async (tx) => {
            const removed = await tx.grade.delete({ where: { id: gradeId }, include: { student: true, subject: true } });
            return {
                result: removed,
                entityId: gradeKey(removed.student.studentId, removed.subject.subjectCode, removed.term),
                detail: { changes: diffFields(removed, null, GRADE_AUDIT_FIELDS) }
            };
        });
        res.json({ success: true, message: `Grade ${id} removed.` });
    } catch (err) {
        if (err.code === 'P2025') {
            await auditFailure(audit, 404, 'No grade with this id exists.');
            return res.status(404).json({ success: false, message: `Grade ${id} not found.` });
        }
        console.error("Grade deletion error:", err);
        await auditFailure(audit, 500, 'The grade could not be removed.');
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

    if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
        return res.status(400).json({ success: false, message: "email and password are required." });
    }
    // A single address with no spaces. Besides being what an email is, an
    // account email appears inside WEVA's audit narratives, and the
    // dashboard's verdict reader relies on it containing no space
    // (middleware/securityMiddleware.js#readVerdict).
    if (email.length > 255 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, message: "Enter a valid email address." });
    }
    if (password.length < 8) {
        return res.status(400).json({ success: false, message: "Password must be at least 8 characters." });
    }

    // Records the new account's email and role - never the password, or
    // its hash.
    const audit = auditEntry(req, 'ADMIN_CREATE', 'AdminAccount', email);
    try {
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) {
            await auditFailure(audit, 409, 'An account with this email already exists.');
            return res.status(409).json({ success: false, message: `An account with email ${email} already exists.` });
        }

        // Hashed before the transaction opens: bcrypt is deliberately slow,
        // and a transaction should not sit open waiting on it.
        const passwordHash = await bcrypt.hash(password, 10);
        const newAdmin = await withAudit(prisma, { ...audit, statusCode: 201 }, async (tx) => {
            const created = await tx.user.create({ data: { email, passwordHash, role: 'admin' } });
            return { result: created, detail: { changes: diffFields(null, created, ['email', 'role']) } };
        });

        res.status(201).json({
            success: true,
            message: `Admin account created for ${email}.`,
            admin: { id: newAdmin.id, email: newAdmin.email, role: newAdmin.role },
            createdBy: req.user.email
        });
    } catch (err) {
        console.error("Admin account creation error:", err);
        await auditFailure(audit, 500, 'The admin account could not be created.');
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
    // Recorded as what it is today: a request, with nothing performed.
    await recordAudit(prisma, {
        ...auditEntry(req, 'BACKUP_REQUEST', 'Database', 'engine backup'),
        outcome: 'SUCCESS', statusCode: 200,
        detail: { note: 'Request received. Placeholder - no backup was performed.' }
    });
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
    await recordAudit(prisma, {
        ...auditEntry(req, 'RESTORE_REQUEST', 'Database', 'engine restore'),
        outcome: 'SUCCESS', statusCode: 200,
        detail: { note: 'Request received. Placeholder - no restore was performed.' }
    });
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
// ERROR HANDLING - registered after every route, so they only see what
// nothing else handled. Unknown API paths get a JSON 404, and any error -
// malformed JSON, a bug in a handler - gets a JSON body with no stack
// trace, whatever NODE_ENV is (see middleware/errorHandlers.js).
// ---------------------------------------------------------------------
app.use('/api', apiNotFound);
app.use(jsonErrorHandler);

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

/** The listening server, kept so the shutdown handler below can close it. */
let server;

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

    server = https.createServer(httpsOptions, app).listen(PORT, () => {
        console.log("--------------------------------------------------");
        console.log(`🟢 SYSTEM ONLINE (HTTPS): Server is actively listening on https://localhost:${PORT}`);
        console.log("--------------------------------------------------");
    });
} else {
    server = app.listen(PORT, () => {
        console.log("--------------------------------------------------");
        console.log(`🟢 SYSTEM ONLINE: Server is actively listening on Port ${PORT}`);
        console.log("--------------------------------------------------");
    });
}

// ---------------------------------------------------------------------
// GRACEFUL SHUTDOWN
// ---------------------------------------------------------------------
// Render sends SIGTERM before every deploy, restart and free-tier
// spin-down, and kills the process outright if it is still running about
// 30 s later. Left to Node's default, SIGTERM exits on the spot: requests
// in flight are cut off mid-response (a grade save, a JSON snapshot
// download) and Prisma's pooled connections are dropped without being
// closed, so RDS keeps them open until they time out on its side. Instead,
// stop accepting new connections, let in-flight requests finish, close the
// pool, then exit. SIGINT (Ctrl+C in a local terminal) takes the same
// path; a second signal skips the wait.
//
// The 10 s cap is a backstop well inside Render's grace period: a request
// that never finishes (e.g. a stalled snapshot stream) must not keep the
// process alive until Render kills it mid-cleanup.
const SHUTDOWN_TIMEOUT_MS = 10_000;
let shuttingDown = false;

/**
 * @param {string} signal - The signal that triggered the shutdown, for the log.
 * @returns {void}
 */
function shutdown(signal) {
    if (shuttingDown) {
        console.log(`[SHUTDOWN] ${signal} received again - exiting now.`);
        process.exit(1);
    }
    shuttingDown = true;
    console.log(`[SHUTDOWN] ${signal} received - finishing in-flight requests...`);

    setTimeout(() => {
        console.error(`[SHUTDOWN] Requests still open after ${SHUTDOWN_TIMEOUT_MS / 1000} s - forcing exit.`);
        process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS).unref();

    // close() stops new connections and, on Node 19+, also closes idle
    // keep-alive ones (the dashboard's pollers hold some open); its callback
    // runs once the last in-flight request has finished.
    server.close(async () => {
        try {
            await prisma.$disconnect();
        } catch (err) {
            console.error('[SHUTDOWN] Could not close database connections cleanly:', err.message);
        }
        console.log('[SHUTDOWN] Closed cleanly.');
        process.exit(0);
    });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
