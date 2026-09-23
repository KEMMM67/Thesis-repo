import { getFeatures, updateFeatures, isAuthAttemptEndpoint } from "../core/monitor.js";
import { getBaseline, updateBaseline } from "../core/profiler.js";
import { computeScore, defaultWevaConfig } from "../core/scorer.js";
import { decideAction, defaultDecisionConfig } from "../core/decisionEngine.js";
import { applyMitigation } from "../core/mitigation.js";
import { countRecentAttempts, recordAttempt } from "../core/ipAttempts.js";
import { getClientIdentity } from "./clientIdentity.js";

/**
 * Builds the request pipeline stage that scores every request for
 * anomalous behavior and enforces the resulting mitigation verdict.
 *
 * Orchestrates the anomaly-detection subsystem end to end: derives the
 * request's behavioral features (core/monitor.js), compares them against
 * the device's learned baseline (core/profiler.js), computes an anomaly
 * score (core/scorer.js), resolves a mitigation decision
 * (core/decisionEngine.js), persists an auditable record of the
 * evaluation, and enforces the decision (core/mitigation.js).
 *
 * Two identities, highest score wins. Every request is scored against its
 * device (the x-device-id header, or its IP when it sends none - see
 * middleware/clientIdentity.js). A login or OTP attempt made before
 * authentication is additionally scored against its IP's recent attempts
 * (core/ipAttempts.js), and the higher of the two scores decides. The
 * device ID is client-controlled: a bot that sends a new one with every
 * guess has no device history to escalate, but all of its guesses still
 * land on one IP history. Authenticated requests are judged by device only -
 * they already carry a server-verified identity (JWT + session), and scoring
 * their IP as well would let one attacker behind a shared campus IP lock out
 * every student and administrator already signed in from that network.
 *
 * The behavioral state getFeatures()/getBaseline() read and write here -
 * per-device request history, login-attempt counts, and EMA baselines -
 * is backed by MemoryStateStore (core/stateStore.js) rather than the bare
 * objects those two modules used to hold directly, so a device that goes
 * idle for 30+ minutes is eventually evicted instead of sitting in memory
 * for the lifetime of the process. See core/monitor.js and
 * core/profiler.js.
 *
 * This module never imports Prisma (or any other storage client) itself:
 * persistence and identity lookup are delegated entirely to the
 * `auditSink` and `identityResolver` ports injected here (see
 * core/ports.js), and `ipTrackingStore` is passed straight through to
 * core/mitigation.js#applyMitigation. The default, Prisma-backed
 * implementations are constructed once in server.js via core/weva.js's
 * createWeva() and injected there - this file has no idea, and does not
 * need to know, what actually persists that state.
 *
 * @param {object} deps
 * @param {import("../core/ports.js").AuditSink} deps.auditSink
 * @param {import("../core/ports.js").IpTrackingStore} deps.ipTrackingStore
 * @param {import("../core/ports.js").IdentityResolver} deps.identityResolver
 * @param {object} [deps.wevaConfig] - Overrides for core/scorer.js#computeScore; defaults to defaultWevaConfig (this app's exact current tuning) when omitted.
 * @param {object} [deps.decisionConfig] - Overrides for core/decisionEngine.js#decideAction; defaults to defaultDecisionConfig when omitted.
 * @returns {import("express").RequestHandler} Express middleware. Calls
 *          `next()` unless the request was blocked or throttled.
 */
export function createSecurityMiddleware({ auditSink, ipTrackingStore, identityResolver, wevaConfig = defaultWevaConfig, decisionConfig = defaultDecisionConfig }) {
    return async function securityMiddleware(req, res, next) {
        const user = req.user?.email || "unauthenticated";
        const role = req.user?.role || "guest";

        let userId = null;
        if (req.user?.email) {
            try {
                const identity = await identityResolver.resolve(req.user.email);
                userId = identity?.id ?? null;
            } catch (err) {
                console.error("User ID resolution failed during security logging:", err.message);
                userId = null;
            }
        }

        // req.baseUrl + req.path, not req.path alone: Express rewrites req.url
        // (and so req.path) relative to the current mount point while
        // dispatching into a sub-router, restoring it afterward. Every
        // endpoint in this app is registered directly on `app` (e.g.
        // app.post("/api/students", ...) in server.js) EXCEPT /login and
        // /verify-otp, which live in routes/authRoutes.js and are reached via
        // app.use("/api", authRoutes) - so for exactly those two routes,
        // req.path alone resolves to "/login"/"/verify-otp" (the /api prefix
        // already stripped by that mount), which matches no entry in
        // core/scorer.js#endpointWeights and silently falls back to the
        // default endpoint weight (1x) instead of their configured 2x -
        // roughly doubling the number of attempts WEVA tolerates before
        // THROTTLE/BLOCK on precisely the two credential-verification
        // endpoints that need it most. req.baseUrl ("/api" inside that
        // sub-router, "" for a route registered directly on `app`) added back
        // reconstructs the full path either way.
        const endpoint = req.baseUrl + req.path;
        const { ip, deviceKey } = getClientIdentity(req);
        const scoreIp = !req.user && isAuthAttemptEndpoint(endpoint);

        // ---- One synchronous step: read history, score, record. ----
        // Nothing between here and the end of this block may `await`. Node
        // runs one callback at a time, so a request that reaches this block
        // sees every request that reached it before - including ones still
        // waiting on the database writes further down. This request used to
        // be recorded only AFTER those two awaited writes, so simultaneous
        // requests all read the same stale history: against the real server,
        // the first 9 of 20 parallel login attempts from one device each saw
        // zero prior attempts, scored 0 (ALLOW), and went on to bcrypt.
        // Recorded here instead, the same burst scores 0, 30, then 100 (the
        // 3rd request, 2 attempts inside ~1 ms = 2000 req/s, x 2 x 2 x 5,
        // clamped) and is BLOCKed from its third request on.
        const deviceFeatures = getFeatures(deviceKey, endpoint);
        const device = computeScore(deviceFeatures, getBaseline(deviceKey), wevaConfig);
        const ipResult = scoreIp
            ? computeScore({ requestRate: 0, loginAttempts: countRecentAttempts(ip), endpoint }, { requestRate: 0 }, wevaConfig)
            : null;

        updateFeatures(deviceKey, endpoint);
        updateBaseline(deviceKey, deviceFeatures);
        if (scoreIp) recordAttempt(ip);
        // ---- End of the synchronous step. ----

        // Ties go to the device: blocking the narrower identity is enough
        // when both tell the same story (one bot on its own IP), and it
        // keeps everyone else behind that IP unaffected.
        const ipDecides = ipResult !== null && ipResult.score > device.score;
        const { score, breakdown } = ipDecides ? ipResult : device;
        const decision = decideAction(score, role, decisionConfig);

        if (ipResult) {
            console.log(`[SECURITY] Device: ${deviceKey} (score ${device.score}) | IP: ${ip} (score ${ipResult.score}) | Target User: ${user} | Final: ${score} via ${ipDecides ? 'IP' : 'device'} (${breakdown.formula}) | Decision: ${decision}`);
        } else {
            console.log(`[SECURITY] Device: ${deviceKey} | Target User: ${user} | Score: ${score} (${breakdown.formula}) | Decision: ${decision}`);
        }

        const risk = decision === 'BLOCK' ? 'CRITICAL' : decision === 'THROTTLE' ? 'HIGH' : decision === 'LOG' ? 'MEDIUM' : 'LOW';

        // The " | " delimiter separates the human-readable narrative from the
        // machine-precise formula using one fixed sequence, so
        // public/admin_dashboard.js can split this column back into two
        // cleanly-styled pieces without a fragile regex (see fetchLogs()).
        const narrative = ipDecides
            ? `IP ${ip} triggered ${decision} (recent login attempts from any device; device ${deviceKey} alone scored ${device.score})`
            : `Device ${deviceKey} triggered ${decision}`;
        const reasonText = `${narrative} | ${breakdown.formula}`;

        await auditSink.recordEvaluation({
            userEmail: user,
            userId,
            score,
            riskLevel: risk,
            actionTaken: decision,
            reason: reasonText,
            eventType: 'SECURITY_EVALUATION'
        });

        // Every identity scored above is checked for an existing block; the
        // one that produced the verdict goes first, since a new BLOCK is
        // recorded against it alone (see core/mitigation.js).
        const identifiers = !scoreIp || ip === deviceKey
            ? [deviceKey]
            : ipDecides ? [ip, deviceKey] : [deviceKey, ip];
        const blocked = await applyMitigation(decision, res, identifiers, ipTrackingStore);

        if (blocked) return;

        next();
    };
}
