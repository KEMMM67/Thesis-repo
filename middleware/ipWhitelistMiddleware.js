import { securityConfig } from "../config/securityConfig.js";
import { isWhitelistEnabled, parseAllowedAdminNetworks, isAllowedAdminIp } from "../config/adminNetworks.js";
import { getIntrusionScore } from "../core/scorer.js";
import { normalizeIp, readLoginPortal } from "./clientIdentity.js";

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
 * Persisting a rejected attempt is delegated entirely to the `auditSink`
 * and `ipTrackingStore` ports (see core/ports.js) injected into the two
 * factories below; the default, Prisma-backed implementations are
 * constructed once in server.js via core/weva.js's createWeva().
 * `isEnabled()`/`getAllowedNetworks()` still
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
 *   1. isEnabled() and getAllowedNetworks() read process.env fresh on
 *      every call rather than caching a decision at module load - flipping
 *      ENABLE_IP_WHITELIST in .env and restarting the server is the
 *      *only* step needed to disable enforcement entirely, with no other
 *      state to reset.
 *
 *   2. normalizeIp() (middleware/clientIdentity.js, shared with WEVA's IP
 *      layer) strips Node's IPv4-mapped IPv6 notation
 *      (`::ffff:127.0.0.1` -> `127.0.0.1`) before every comparison. This
 *      is what Express's req.ip commonly reports for a plain IPv4
 *      loopback connection on this platform's dual-stack listener -
 *      confirmed empirically against this exact server, not assumed -
 *      and without normalizing it, the shipped default
 *      ALLOWED_ADMIN_IPS=127.0.0.1,::1 could fail to match the
 *      developer's own machine.
 *
 * ALLOWED_ADMIN_IPS takes CIDR ranges as well as single addresses
 * ("203.0.113.0/24"), because a venue's network can reach the internet
 * through more than one public IP. Parsing, the limits that stop a typo
 * from widening access, and the startup log line live in
 * config/adminNetworks.js.
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
 *   - createIpWhitelistForAdminLogin: portal-aware enforcement, for POST
 *     /api/login specifically. That route is shared by both the student
 *     and admin portals and has no req.user yet to consult (login is
 *     pre-auth by definition), so it cannot use the unconditional
 *     variant without also blocking students from an unlisted IP - it
 *     enforces only for requests from the Admin Portal; see its own doc
 *     comment below for why that, and not the account's role, decides.
 */

/**
 * @returns {boolean} Whether whitelist enforcement is currently active - see config/adminNetworks.js#isWhitelistEnabled for why anything but "true" means off.
 */
function isEnabled() {
    return isWhitelistEnabled(process.env);
}

/**
 * @returns {import("node:net").BlockList} The ALLOWED_ADMIN_IPS addresses and ranges as a matcher. Re-parsed from process.env on every call - see this file's @fileoverview. Ignored entries are reported once, at startup (server.js), not here on every request.
 */
function getAllowedNetworks() {
    return parseAllowedAdminNetworks(process.env.ALLOWED_ADMIN_IPS).blockList;
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
        if (isAllowedAdminIp(getAllowedNetworks(), requestIp)) return next();

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
 * Builds the network-origin gate for POST /api/login specifically.
 *
 * Every other route this module gates is admin-only by construction, so
 * createIpWhitelistMiddleware's returned middleware can enforce
 * unconditionally. Login is different: it is the single endpoint both
 * the Student and Admin Portals post to, so this gate enforces only for a
 * request that declares the Admin Portal
 * (middleware/clientIdentity.js#readLoginPortal) - a Student Portal login
 * is never subject to it, at any IP, satisfying "this must not block
 * Student logins, only Admins."
 *
 * It keys on the portal, not on the account. It used to look up the
 * submitted email's role and refuse only admin emails, before any password
 * check - so from outside the campus, trying an email told anyone whether
 * it belonged to an administrator: 403 "Network Access Denied" for admins,
 * 401 for everyone else. Now the Admin Portal answers every outside
 * request the same way, whatever email is typed. The account-level rule
 * that replaces the role lookup - administrators may sign in only through
 * the Admin Portal - is enforced after the password check in
 * controllers/authController.js#login, where the wrong portal fails exactly
 * like a wrong password, so the Student Portal cannot be used as a way
 * around this gate either.
 *
 * @param {object} deps
 * @param {import("../core/ports.js").AuditSink} deps.auditSink
 * @param {import("../core/ports.js").IpTrackingStore} deps.ipTrackingStore
 * @returns {import("express").RequestHandler}
 */
export function createIpWhitelistForAdminLogin({ auditSink, ipTrackingStore }) {
    return async function ipWhitelistForAdminLogin(req, res, next) {
        if (!isEnabled()) return next();
        if (readLoginPortal(req) !== 'admin') return next();

        const requestIp = normalizeIp(req.ip);
        if (isAllowedAdminIp(getAllowedNetworks(), requestIp)) return next();

        await recordIntrusion(auditSink, ipTrackingStore, requestIp, req.baseUrl + req.path);
        rejectDisallowedIp(res);
    };
}
