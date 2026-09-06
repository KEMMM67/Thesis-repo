import { securityConfig } from "../config/securityConfig.js";
import { getIntrusionScore } from "../core/scorer.js";

/**
 * @fileoverview Network-perimeter access control for the Admin Portal,
 * simulating a campus-intranet-only deployment (ENABLE_IP_WHITELIST /
 * ALLOWED_ADMIN_IPS in .env). This is a coarser, earlier gate than WEVA's
 * behavioral scoring (middleware/securityMiddleware.js): where WEVA judges
 * *how* a device is behaving over time, this judges *where* the request
 * is coming from before anything else runs, so a disallowed network
 * origin is rejected before a single JWT verification, database lookup,
 * or behavioral score is attempted.
 *
 * This module never imports Prisma (or any other storage client) itself.
 * Persisting a rejected attempt and resolving a submitted email's role are
 * delegated entirely to the `auditSink`, `ipTrackingStore`, and
 * `identityResolver` ports (see core/ports.js) injected into the two
 * factories below; the default, Prisma-backed implementations are
 * constructed once in server.js via core/weva.js's createWeva().
 * `isEnabled()`/`getAllowedIps()` still
 * read `process.env` directly further down - that is deliberate and
 * unrelated to storage: they are the *policy* (is enforcement on, and
 * from where), not a database dependency, and this file reading its own
 * environment configuration is not the coupling this refactor is
 * removing.
 *
 * Two things matter more here than in most middleware in this codebase,
 * because this gates the developer's own access, including during a live
 * demo where getting it wrong means losing access to the thing being
 * demonstrated:
 *
 *   1. isEnabled() and getAllowedIps() read process.env fresh on every
 *      call rather than caching a decision at module load - flipping
 *      ENABLE_IP_WHITELIST in .env and restarting the server is the
 *      *only* step needed to disable enforcement entirely, with no other
 *      state to reset.
 *
 *   2. normalizeIp() strips Node's IPv4-mapped IPv6 notation
 *      (`::ffff:127.0.0.1` -> `127.0.0.1`) before every comparison. This
 *      is what Express's req.ip commonly reports for a plain IPv4
 *      loopback connection on this platform's dual-stack listener -
 *      confirmed empirically against this exact server, not assumed -
 *      and without normalizing it, the shipped default
 *      ALLOWED_ADMIN_IPS=127.0.0.1,::1 could fail to match the
 *      developer's own machine.
 *
 * Two exports, for two different situations:
 *
 *   - createIpWhitelistMiddleware: unconditional enforcement, for any
 *     route that is admin-only *by construction* - every /api/admin/*
 *     route, the other admin-role-gated resource routes in server.js, and
 *     POST /api/verify-otp (the OTP step exists only in the admin login
 *     chain - see controllers/authController.js). Mount its returned
 *     middleware first, before authMiddleware, on all of those.
 *
 *   - createIpWhitelistForAdminLogin: role-aware enforcement, for POST
 *     /api/login specifically. That route is shared by both the student
 *     and admin portals and has no req.user yet to consult (login is
 *     pre-auth by definition), so it cannot use the unconditional
 *     variant without also blocking students from an unlisted IP -
 *     see its own doc comment below for how it resolves that.
 */

/**
 * @returns {boolean} Whether whitelist enforcement is currently active. Anything other than the literal string "true" (case-insensitive) - including the variable being unset - is treated as disabled, so a missing or malformed .env value fails open rather than locking every admin out.
 */
function isEnabled() {
    return (process.env.ENABLE_IP_WHITELIST || '').trim().toLowerCase() === 'true';
}

/**
 * Strips Node's IPv4-mapped IPv6 prefix, so "::ffff:127.0.0.1" and
 * "127.0.0.1" compare equal. See this file's @fileoverview.
 *
 * @param {string} ip
 * @returns {string}
 */
function normalizeIp(ip) {
    if (!ip) return ip;
    return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

/**
 * @returns {string[]} Normalized ALLOWED_ADMIN_IPS entries. Re-parsed from process.env on every call - see this file's @fileoverview.
 */
function getAllowedIps() {
    return (process.env.ALLOWED_ADMIN_IPS || '')
        .split(',')
        .map(ip => normalizeIp(ip.trim()))
        .filter(Boolean);
}

/**
 * Sends the network-denial response. A fixed shape distinct from every
 * other rejection in this codebase (WEVA's THROTTLE/BLOCK responses use
 * { success: false, message } - see core/mitigation.js) because this is a
 * categorically different kind of rejection: not "you were rate-limited"
 * but "this network cannot reach this portal at all," which the
 * dedicated `error` field makes unambiguous to any client-side handling
 * that inspects it.
 *
 * @param {import("express").Response} res
 * @returns {void}
 */
function rejectDisallowedIp(res) {
    res.status(403).json({
        error: "Network Access Denied",
        message: "Admin portal can only be accessed from the Campus Intranet."
    });
}

/**
 * Persists a blocked network-origin attempt via the injected `auditSink`
 * and `ipTrackingStore` (see core/ports.js), scored via
 * core/scorer.js#getIntrusionScore(). Marking the offending identifier
 * blocked in `ipTrackingStore` means a disallowed IP that reaches a
 * *different*, non-admin-gated route after this rejection (e.g. the
 * student portal) is still caught there for the remainder of the block
 * window, via core/mitigation.js#applyMitigation - without
 * middleware/securityMiddleware.js needing any awareness that this
 * middleware exists.
 *
 * Recorded against `userEmail: 'unauthenticated'`, matching how
 * middleware/securityMiddleware.js already attributes every pre-auth WEVA
 * event - an unauthorized network origin has, by definition, no
 * authenticated identity yet to attribute it to.
 *
 * @param {import("../core/ports.js").AuditSink} auditSink
 * @param {import("../core/ports.js").IpTrackingStore} ipTrackingStore
 * @param {string} ip - The normalized, disallowed IP that made the request.
 * @param {string} path - The full path it attempted to reach.
 * @returns {Promise<void>}
 */
async function recordIntrusion(auditSink, ipTrackingStore, ip, path) {
    const { score, breakdown } = getIntrusionScore(`disallowed network origin ${ip} reached ${path}`);
    const blockedUntil = new Date(Date.now() + securityConfig.mitigation.temporaryBlockMs);

    // Deliberately includes the literal word "BLOCK": public/admin_dashboard.js's
    // fetchLogs() colors a log row's badge red when its description contains
    // that substring (mirroring how middleware/securityMiddleware.js's own
    // BLOCK verdicts already read "Device X triggered BLOCK | ..."), so this
    // event renders with the same visual severity on the Security Logs table.
    const description = `IP ${ip} triggered BLOCK (unauthorized network origin - admin portal is Campus-Intranet-restricted) | ${breakdown.formula}`;

    const results = await Promise.allSettled([
        auditSink.recordEvaluation({
            userEmail: 'unauthenticated',
            userId: null,
            score,
            riskLevel: 'CRITICAL',
            actionTaken: 'BLOCK',
            reason: description,
            eventType: 'NETWORK_ACCESS_DENIED'
        }),
        ipTrackingStore.block(ip, blockedUntil)
    ]);

    const labels = ['auditSink.recordEvaluation', 'ipTrackingStore.block'];
    results.forEach((result, i) => {
        if (result.status === 'rejected') {
            console.error(`[ipWhitelistMiddleware] ${labels[i]} failed:`, result.reason.message);
        }
    });
}

/**
 * Builds the unconditional network-origin gate for routes that are
 * admin-only by construction. See this file's @fileoverview for the full
 * list and for why its returned middleware must be mounted before
 * authMiddleware.
 *
 * @param {object} deps
 * @param {import("../core/ports.js").AuditSink} deps.auditSink
 * @param {import("../core/ports.js").IpTrackingStore} deps.ipTrackingStore
 * @returns {import("express").RequestHandler}
 */
export function createIpWhitelistMiddleware({ auditSink, ipTrackingStore }) {
    return async function ipWhitelistMiddleware(req, res, next) {
        if (!isEnabled()) return next();

        const requestIp = normalizeIp(req.ip);
        if (getAllowedIps().includes(requestIp)) return next();

        // req.baseUrl + req.path, not req.path alone: this middleware is also
        // mounted inside routes/authRoutes.js's sub-router (for
        // POST /api/verify-otp), where req.path alone would already be
        // stripped of the "/api" mount prefix - see the identical reasoning
        // (and the bug it previously caused) in middleware/securityMiddleware.js.
        await recordIntrusion(auditSink, ipTrackingStore, requestIp, req.baseUrl + req.path);
        rejectDisallowedIp(res);
    };
}

/**
 * Builds the role-aware network-origin gate for POST /api/login
 * specifically.
 *
 * Every other route this module gates is admin-only by construction, so
 * createIpWhitelistMiddleware's returned middleware can enforce
 * unconditionally. Login is different: it is the single shared endpoint
 * for both the student and admin portals (see controllers/authController.js),
 * and - being pre-auth by definition - has no req.user yet for this
 * middleware to consult. So this peeks at the *submitted* email's role,
 * via the injected `identityResolver`, before deciding whether to enforce
 * at all: a student's login is never subject to this check, at any IP,
 * satisfying "this must not block Student logins, only Admins." An email
 * that resolves to no account, or to a non-admin role, is passed through
 * unconditionally either way - the normal password check in
 * controllers/authController.js#login is what (correctly) rejects an
 * invalid one, not this middleware; this middleware only ever *adds* a
 * rejection on top of that, for a confirmed admin email from a
 * disallowed network.
 *
 * @param {object} deps
 * @param {import("../core/ports.js").AuditSink} deps.auditSink
 * @param {import("../core/ports.js").IpTrackingStore} deps.ipTrackingStore
 * @param {import("../core/ports.js").IdentityResolver} deps.identityResolver
 * @returns {import("express").RequestHandler}
 */
export function createIpWhitelistForAdminLogin({ auditSink, ipTrackingStore, identityResolver }) {
    return async function ipWhitelistForAdminLogin(req, res, next) {
        if (!isEnabled()) return next();

        const email = req.body?.email;
        if (!email) return next();

        let identity;
        try {
            identity = await identityResolver.resolve(email);
        } catch (err) {
            console.error("[ipWhitelistMiddleware] Role lookup failed, allowing through to the normal login flow:", err.message);
            return next();
        }

        if (identity?.role !== 'admin') return next();

        const requestIp = normalizeIp(req.ip);
        if (getAllowedIps().includes(requestIp)) return next();

        await recordIntrusion(auditSink, ipTrackingStore, requestIp, req.baseUrl + req.path);
        rejectDisallowedIp(res);
    };
}
