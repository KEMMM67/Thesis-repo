/**
 * @fileoverview weva-security: WEVA, the Weighted Endpoint & Velocity
 * Algorithm from our thesis Student Information System, as Express
 * middleware.
 *
 *     app.use(express.json());
 *     app.use(wevaSecurity({ authPaths: ['/api/login'] }));
 *
 * Each request to a listed route runs the pipeline of the thesis build's
 * middleware/securityMiddleware.js:
 *
 *     identify (device ID + IP) -> score (lib/scorer.js) -> decide (lib/decision.js)
 *       -> pass it on, or answer 429 / 403 (lib/mitigation.js)
 *
 * Only routes listed in `authPaths` or `endpointWeights` are scored; every
 * other request passes through untouched. The thesis build attaches WEVA route
 * by route for the same reason: static files, polling and a page's parallel
 * API calls would otherwise read as a burst of automation.
 */
import { computeScore, DEFAULT_SCORING } from './lib/scorer.js';
import { decideAction, DEFAULT_THRESHOLDS } from './lib/decision.js';
import { DeviceTracker, IpAttemptWindow } from './lib/tracker.js';
import { applyMitigation, MemoryBlockStore } from './lib/mitigation.js';
import { identifyClient, normalizeAccount, requestPath, compileRoutes } from './lib/request.js';

export { computeScore, decideAction, MemoryBlockStore };

/** Weight of an auth path missing from endpointWeights: the thesis's 2x authentication tier. */
const AUTH_PATH_WEIGHT = 2;

/** Verdicts that let a request through - the only traffic a baseline may learn from. */
const PASSING = new Set(['ALLOW', 'LOG']);

/** Methods that submit no credentials: a GET of a login page is not a login attempt. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const RISK_LEVELS = { ALLOW: 'LOW', LOG: 'MEDIUM', THROTTLE: 'HIGH', BLOCK: 'CRITICAL' };

const DEFAULTS = {
    ...DEFAULT_SCORING,
    thresholds: DEFAULT_THRESHOLDS,
    authPaths: [],
    deviceIdHeader: 'x-device-id',
    windowMs: 30_000,
    emaAlpha: 0.1,
    blockMs: 60_000,
    throttleRetryAfterSeconds: 15,
    getTargetAccount: req => req.body?.email ?? req.body?.username,
    onEvaluation: logVerdict
};

/**
 * Creates the middleware. Each call keeps its own history and block store.
 *
 * @param {object} [options] - All optional; see README.md for the full list.
 * @param {string[]} [options.authPaths] - Route patterns where any request but GET/HEAD/OPTIONS is a credential check.
 * @param {Record<string, number>} [options.endpointWeights] - Other routes to guard: pattern -> weight (1 routine ... 4 destructive).
 * @param {{suspicious?: number, critical?: number, block?: number}} [options.thresholds] - Default 25 / 60 / 85.
 * @param {number} [options.throttleRetryAfterSeconds] - Retry-After sent with a 429. Default 15.
 * @param {number} [options.blockMs] - How long a BLOCK lasts. Default 60 000.
 * @param {(evaluation: object) => unknown} [options.onEvaluation] - Receives every evaluation. Default: logs LOG/THROTTLE/BLOCK.
 * @param {{findStatus: Function, block: Function, clear: Function}} [options.blockStore] - Default: in memory.
 * @returns {(req: object, res: object, next: Function) => void}
 */
export function wevaSecurity(options = {}) {
    const config = resolveOptions(options);
    const devices = new DeviceTracker(config);
    const ipWindow = new IpAttemptWindow(config);
    const matchScoredRoute = compileRoutes(Object.keys(config.endpointWeights));
    const matchAuthRoute = compileRoutes(config.authPaths);

    async function evaluate(req, res) {
        const path = requestPath(req);
        const endpoint = matchScoredRoute(path);
        // Unlisted routes and CORS preflights pass through untouched.
        if (endpoint === null || req.method === 'OPTIONS') return false;

        const { ip, deviceKey } = identifyClient(req, config.deviceIdHeader);
        const authAttempt = !SAFE_METHODS.has(req.method) && matchAuthRoute(path) !== null;
        const account = authAttempt ? normalizeAccount(config.getTargetAccount(req)) : '';

        // ---- One synchronous step: read history, score, record, learn. ----
        // Nothing in here may `await`. Node runs one callback at a time, so
        // each request sees every request that arrived before it, and a burst
        // of parallel guesses cannot all read the same empty history.
        const features = devices.features(deviceKey, endpoint);
        const identities = [{
            kind: 'device', key: deviceKey,
            result: computeScore(features, devices.baseline(deviceKey), config)
        }];
        if (authAttempt) {
            // The IP layer catches a bot that sends a new device ID with every
            // guess: all its guesses land on one address. No velocity term and
            // no baseline - the combined rate of everyone behind a NAT
            // describes nobody.
            identities.push({
                kind: 'ip', key: ip,
                result: computeScore({ requestRate: 0, loginAttempts: ipWindow.count(ip), endpoint }, { requestRate: 0 }, config)
            });
        }

        // The device records every request, refused or not.
        devices.recordRequest(deviceKey);
        if (authAttempt) devices.recordAttempt(deviceKey, account);

        // A baseline learns only from traffic that is let through. Learning
        // from a throttled flood would teach it that the flood is normal.
        if (PASSING.has(decideAction(identities[0].result.score, config.thresholds))) {
            devices.learn(deviceKey, features);
        }

        // The highest score decides; a tie goes to the device, the narrowest identity.
        const deciding = identities.reduce((best, candidate) => (candidate.result.score > best.result.score ? candidate : best));
        const { score, breakdown } = deciding.result;
        const decision = decideAction(score, config.thresholds);

        // The IP window counts only attempts that go on to the password check.
        // On a shared IP most refused attempts are other people's; counting
        // them let a few typos behind one campus NAT lock out everyone there.
        if (authAttempt && PASSING.has(decision)) ipWindow.record(ip, account);
        // ---- End of the synchronous step. ----

        req.weva = {
            score,
            decision,
            breakdown,
            /**
             * Call once the user is fully signed in (after the last factor,
             * such as an OTP). Settles this client's failed attempts at that
             * account only; settling every account would let an attacker wipe
             * their guesses at a victim by signing into their own account.
             */
            loginSucceeded(signedInAccount) {
                const settled = normalizeAccount(signedInAccount);
                devices.settle(deviceKey, settled);
                ipWindow.settle(ip, settled);
            }
        };

        report(config.onEvaluation, {
            time: new Date().toISOString(),
            method: req.method,
            endpoint,
            ip,
            deviceKey,
            scores: Object.fromEntries(identities.map(identity => [identity.kind, identity.result.score])),
            decidedBy: deciding.kind,
            key: deciding.key,
            score,
            decision,
            riskLevel: RISK_LEVELS[decision],
            breakdown
        });

        // Every identity is checked for an active block; the deciding one goes
        // first, since a new BLOCK is recorded against it alone.
        const identifiers = [...new Set([deciding.key, ...identities.map(identity => identity.key)])];
        return applyMitigation(decision, res, identifiers, config);
    }

    return function wevaMiddleware(req, res, next) {
        evaluate(req, res).then(handled => { if (!handled) next(); }, next);
    };
}

export default wevaSecurity;

/**
 * Hands an evaluation to onEvaluation without waiting for it: a slow or
 * failing audit sink must never delay or break the decision it reports.
 */
function report(onEvaluation, evaluation) {
    if (typeof onEvaluation !== 'function') return;
    Promise.resolve()
        .then(() => onEvaluation(evaluation))
        .catch(err => console.error('[WEVA] onEvaluation failed:', err));
}

/** The default onEvaluation: one console line for every verdict above ALLOW. */
function logVerdict({ decision, method, endpoint, decidedBy, key, breakdown }) {
    if (decision === 'ALLOW') return;
    console.log(`[WEVA] ${decision} ${method} ${endpoint} | ${decidedBy} ${key} | ${breakdown.formula}`);
}

function resolveOptions(options) {
    const authPaths = options.authPaths ?? DEFAULTS.authPaths;
    if (!Array.isArray(authPaths)) {
        throw new TypeError('weva-security: authPaths must be an array of route patterns.');
    }

    const config = {
        ...DEFAULTS,
        ...options,
        authPaths,
        // Auth paths are always scored, at the authentication tier unless listed.
        endpointWeights: { ...Object.fromEntries(authPaths.map(path => [path, AUTH_PATH_WEIGHT])), ...options.endpointWeights },
        thresholds: { ...DEFAULTS.thresholds, ...options.thresholds },
        deviceIdHeader: (options.deviceIdHeader ?? DEFAULTS.deviceIdHeader).toLowerCase(),
        blockStore: options.blockStore ?? new MemoryBlockStore()
    };

    // Fail at startup rather than on the first request.
    const { suspicious, critical, block } = config.thresholds;
    if (!(suspicious <= critical && critical <= block)) {
        throw new TypeError('weva-security: thresholds must satisfy suspicious <= critical <= block.');
    }
    for (const [route, weight] of Object.entries(config.endpointWeights)) {
        if (!(typeof weight === 'number' && weight > 0)) {
            throw new TypeError(`weva-security: endpointWeights["${route}"] must be a positive number.`);
        }
    }
    for (const method of ['findStatus', 'block', 'clear']) {
        if (typeof config.blockStore[method] !== 'function') {
            throw new TypeError(`weva-security: blockStore.${method}() is missing.`);
        }
    }
    return config;
}
