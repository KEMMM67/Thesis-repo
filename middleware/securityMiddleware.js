import { getFeatures, updateFeatures, isAuthAttemptEndpoint } from "../core/monitor.js";
import { getBaseline, updateBaseline } from "../core/profiler.js";
import { computeScore, defaultWevaConfig } from "../core/scorer.js";
import { decideAction, defaultDecisionConfig } from "../core/decisionEngine.js";
import { applyMitigation } from "../core/mitigation.js";
import { countRecentAttempts, recordAttempt } from "../core/ipAttempts.js";
import { getClientIdentity, readTargetAccount, accountKey } from "./clientIdentity.js";

/**
 * Verdicts WEVA lets through. An identity's EMA baseline learns from a
 * request only when that identity's own verdict is one of these - learning
 * from throttled or blocked traffic would teach the baseline that the
 * attack is normal. See the baseline-poisoning note on
 * core/profiler.js#updateBaseline.
 */
const LEARNABLE_VERDICTS = new Set(['ALLOW', 'LOG']);

/** How each kind of identity is named in the console log. */
const IDENTITY_LABELS = { device: 'Device', ip: 'IP', account: 'Account' };

/**
 * The fixed shape every WEVA audit narrative starts with - written below,
 * and by middleware/ipWhitelistMiddleware.js for network denials:
 * "<Device|IP|Account> <key> triggered <VERDICT>".
 */
const VERDICT_PATTERN = /^(?:Device|IP|Account) \S+ triggered (ALLOW|LOG|THROTTLE|BLOCK)\b/;

/**
 * Reads the verdict back out of a WEVA audit narrative, for the admin
 * dashboard's Security Logs badges (GET /api/admin/logs in server.js).
 *
 * The dashboard used to color a row by searching its whole description
 * for "ALLOW", "THROTTLE" or "BLOCK" - and part of that description is the
 * client-chosen x-device-id. A device named "DEV-ALLOWED" turned its own
 * BLOCK rows green (reproduced). This reads only the one position the
 * server writes the verdict into, anchored to the start of the narrative.
 * The key in front of it cannot shift that position, because no key can
 * contain a space: device IDs are limited to letters, digits, "_" and "-"
 * (middleware/clientIdentity.js), IPs never contain one, and account emails
 * are refused with one (POST /api/admin/accounts). So
 * "Device ALLOW triggered BLOCK | ..." still reads as BLOCK.
 *
 * @param {string|null|undefined} description - A BehaviorLog description.
 * @returns {"ALLOW"|"LOG"|"THROTTLE"|"BLOCK"|null} The verdict, or null for any other kind of log (e.g. "User logged in successfully.").
 */
export function readVerdict(description) {
    const match = typeof description === 'string' ? VERDICT_PATTERN.exec(description) : null;
    return match ? match[1] : null;
}

/**
 * The endpoint a request is scored as: the Express route pattern that
 * matched it (e.g. "/api/students/:id"), prefixed with its router's mount
 * path - or the concrete path when no route has matched yet.
 *
 * The route pattern is the reliable answer to "which endpoint is this": it
 * is exactly the key core/scorer.js's endpointWeights table uses, whatever
 * shape the IDs in the URL happen to have. The concrete path used to be
 * scored instead, leaving core/scorer.js#normalizePath to recognise IDs by
 * their shape - and it recognised only one-letter IDs, so deleting any of
 * the 15,000 bulk-seeded students ("/api/students/CC25-000001") was
 * weighted 1x instead of 3x, and the audit formula showed it. req.route is
 * set whenever this middleware runs as part of a route
 * (app.put("/api/students/:id", ..., securityMiddleware, handler), as every
 * route in this app does); mounted app-wide with app.use() it is not, and
 * the concrete path - with normalizePath() - is the fallback.
 *
 * req.baseUrl is added back because Express strips a router's mount path
 * while dispatching inside it: for /login and /verify-otp, which live in
 * routes/authRoutes.js mounted at "/api", req.baseUrl is "/api" and the
 * pattern alone is "/login". Without the prefix neither would match its 2x
 * entry in endpointWeights, roughly doubling the attempts WEVA tolerates on
 * the two credential-verification endpoints that need it most.
 *
 * @param {import("express").Request} req
 * @returns {string}
 */
function scoredEndpoint(req) {
    const pattern = req.route?.path;
    return req.baseUrl + (typeof pattern === 'string' ? pattern : req.path);
}

/**
 * Builds the request pipeline stage that scores every request for
 * anomalous behavior and enforces the resulting mitigation verdict.
 *
 * Orchestrates the anomaly-detection subsystem end to end: derives the
 * request's behavioral features (core/monitor.js), compares them against
 * each identity's learned baseline (core/profiler.js), computes an anomaly
 * score (core/scorer.js), resolves a mitigation decision
 * (core/decisionEngine.js), persists an auditable record of the
 * evaluation, and enforces the decision (core/mitigation.js).
 *
 * Every identity a request carries is scored, and the highest score decides
 * (middleware/clientIdentity.js derives them all):
 *
 *   identity  key                   scored for                         strength
 *   device    x-device-id, else IP  every request                      tells apart users behind one IP; client-controlled
 *   IP        req.ip                login/OTP attempts before login    rotating device IDs still land on one IP
 *   account   "user:<id>"           requests from a signed-in user     server-verified (JWT + session); cannot be rotated
 *
 * Before login - device + IP. The device ID is client-controlled: a bot
 * that sends a new one with every guess has no device history to escalate,
 * but all of its guesses still land on one IP history (core/ipAttempts.js).
 *
 * After login - device + account. The device ID can be rotated just as
 * easily with a stolen session token: a random x-device-id on every request
 * made each one a "new device" with no history, and a script deleting
 * records at 20 req/s was never throttled (reproduced: 200 of 200 DELETEs
 * passed). The account key comes from the verified JWT, so all of those
 * requests share one history. Worked example - that script, admin role,
 * DELETE /api/students/:id (3x), a fresh device ID on every request:
 *
 *   request 1   device 0 | account 0 (no history)                    ALLOW
 *   request 2   device 0 | account 0 (one prior request: no rate)    ALLOW
 *   request 3   device 0 | account: 2 requests in 100 ms = 20 req/s
 *               20 x 3 x 1 x 5 = 300 -> 100  >= admin BLOCK (85 + 15) BLOCK
 *
 * The block is recorded against the account key, so every later request on
 * that account is refused for 60 s whatever device ID it claims. The IP is
 * still not scored after login: one attacker behind a shared campus IP must
 * not be able to lock out everyone already signed in from that network.
 *
 * Ties go to the device, the narrowest identity. When device and account
 * tell the same story - one user on one device, the usual case, including
 * the dashboard's Simulate Attack - blocking the device is enough and
 * leaves the account's other devices alone. The account decides only when
 * it scores strictly higher, which happens when its traffic is spread
 * across devices: exactly the rotation case.
 *
 * Learning. Each identity's baseline learns from a request only if that
 * identity's own verdict was ALLOW or LOG (LEARNABLE_VERDICTS). Throttled
 * and blocked traffic is still recorded on the device and the account - it
 * still counts toward velocity and attempts - but it never becomes the
 * "normal" future requests are judged against. The IP's attempt window is
 * the exception: it records only attempts that reach the password check
 * (see the end of the synchronous step for why).
 *
 * The behavioral state getFeatures()/getBaseline() read and write here -
 * per-identity request history, login-attempt ledgers, and EMA baselines -
 * is backed by MemoryStateStore (core/stateStore.js) rather than the bare
 * objects those two modules used to hold directly, so an identity that
 * goes idle for 30+ minutes is eventually evicted instead of sitting in
 * memory for the lifetime of the process. See core/monitor.js and
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

        const endpoint = scoredEndpoint(req);
        const { ip, deviceKey } = getClientIdentity(req);
        const authAttempt = isAuthAttemptEndpoint(endpoint);
        // Which account a login/OTP attempt is aimed at, recorded with the
        // attempt so a successful login settles only its own account's
        // attempts (core/monitor.js#settleDeviceAttempts).
        const account = authAttempt ? readTargetAccount(req) : '';
        const scoreIp = !req.user && authAttempt;
        // The account layer needs the resolved user id. If the account cannot
        // be resolved (deleted since the token was issued, or the lookup
        // failed), the request is scored without it, as before the layer existed.
        const userKey = req.user && userId != null ? accountKey(userId) : null;

        // ---- One synchronous step: read history, score, record, learn. ----
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
        const identities = [{
            kind: 'device', key: deviceKey, features: deviceFeatures,
            result: computeScore(deviceFeatures, getBaseline(deviceKey), wevaConfig)
        }];
        if (userKey) {
            const accountFeatures = getFeatures(userKey, endpoint);
            identities.push({
                kind: 'account', key: userKey, features: accountFeatures,
                result: computeScore(accountFeatures, getBaseline(userKey), wevaConfig)
            });
        }
        if (scoreIp) {
            // No velocity term and no baseline for an IP (core/ipAttempts.js).
            identities.push({
                kind: 'ip', key: ip, features: null,
                result: computeScore({ requestRate: 0, loginAttempts: countRecentAttempts(ip), endpoint }, { requestRate: 0 }, wevaConfig)
            });
        }

        updateFeatures(deviceKey, endpoint, account);
        if (userKey) updateFeatures(userKey, endpoint, account);

        for (const identity of identities) {
            if (identity.features && LEARNABLE_VERDICTS.has(decideAction(identity.result.score, role, decisionConfig))) {
                updateBaseline(identity.key, identity.features);
            }
        }

        // Highest score decides; ties go to the earliest entry - the device.
        const deciding = identities.reduce((best, candidate) => (candidate.result.score > best.result.score ? candidate : best));
        const { score, breakdown } = deciding.result;
        const decision = decideAction(score, role, decisionConfig);

        // The IP's attempt window (core/ipAttempts.js) records an attempt
        // only if this verdict lets it through to the password check. A
        // refused attempt tests no password, so it is no evidence of
        // guessing - and counting it locked whole campuses out. Everyone
        // behind a campus NAT shares one window: four unrelated typos inside
        // 30 s throttled the next student, that refused attempt was recorded
        // as a fifth failure, the next as a sixth, until the IP was BLOCKed;
        // and every student arriving during the 60 s block was recorded too,
        // so the window was full again the moment the block lifted. In the
        // comparison harness (bench/, scenario 6), 400 students signing in
        // over 5 minutes lost 254 of themselves that way; counting only
        // attempts that reach the password check, 7.
        //
        // The cost: the window never holds more than the 4 attempts that
        // bring it to THROTTLE, so the IP layer throttles but no longer
        // blocks. A bot rotating device IDs on one address gets at most 4
        // password checks in any 30 s, rather than 4 and then a 60 s block.
        // The device and account layers are unchanged: they record every
        // attempt, refused or not, and still block.
        //
        // Inside the synchronous step, like the recording above, so
        // simultaneous rotating-ID guesses each see the ones before them.
        if (scoreIp && LEARNABLE_VERDICTS.has(decision)) recordAttempt(ip, account);
        // ---- End of the synchronous step. ----

        const deviceScore = identities[0].result.score;

        if (identities.length > 1) {
            const scored = identities.map(identity => `${IDENTITY_LABELS[identity.kind]}: ${identity.key} (score ${identity.result.score})`).join(' | ');
            console.log(`[SECURITY] ${scored} | Target User: ${user} | Final: ${score} via ${IDENTITY_LABELS[deciding.kind]} (${breakdown.formula}) | Decision: ${decision}`);
        } else {
            console.log(`[SECURITY] Device: ${deviceKey} | Target User: ${user} | Score: ${score} (${breakdown.formula}) | Decision: ${decision}`);
        }

        const risk = decision === 'BLOCK' ? 'CRITICAL' : decision === 'THROTTLE' ? 'HIGH' : decision === 'LOG' ? 'MEDIUM' : 'LOW';

        // The " | " delimiter separates the human-readable narrative from the
        // machine-precise formula using one fixed sequence, so
        // public/admin_dashboard.js can split this column back into two
        // cleanly-styled pieces without a fragile regex (see fetchLogs()).
        // The "Device <key> triggered" wording is also what server.js's
        // unblock route searches for to find a blocked device's last user.
        //
        // "on <METHOD> <endpoint>" names what was requested - the route
        // pattern the endpoint weight in the formula came from. Without it,
        // a log entry said a device scored 45 but not on what, so a 3x
        // DELETE and a 3x PUT on the same record read identically. It sits
        // after the verdict, so readVerdict()'s fixed position is unchanged.
        const target = `${req.method} ${endpoint}`;
        const narrative = {
            device: `Device ${deviceKey} triggered ${decision} on ${target}`,
            ip: `IP ${ip} triggered ${decision} on ${target} (recent login attempts from any device; device ${deviceKey} alone scored ${deviceScore})`,
            account: `Account ${user} triggered ${decision} on ${target} (requests from every device signed in to it; device ${deviceKey} alone scored ${deviceScore})`
        }[deciding.kind];
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

        // Every identity is checked for an existing block; the one that
        // produced the verdict goes first, since a new BLOCK is recorded
        // against it alone (see core/mitigation.js). A request with no device
        // header uses its IP as its device key, so duplicates are dropped.
        const identifiers = [...new Set([deciding.key, ...identities.map(identity => identity.key)])];
        const blocked = await applyMitigation(decision, res, identifiers, ipTrackingStore);

        if (blocked) return;

        next();
    };
}
