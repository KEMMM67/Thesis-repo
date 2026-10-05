/**
 * @fileoverview The four algorithms the comparison runs (bench/run-comparison.js).
 *
 * Each entry's create() is called once per run, after the simulator has
 * reset every module and started the fake clock (bench/simulator.js), and
 * returns:
 *
 *   - middleware(req, res, next): the guard, placed in front of the same
 *     routes WEVA guards - the login endpoint and the admin routes.
 *   - afterApp(req, spec, outcome), optional: told how the application
 *     answered a request the guard let through.
 *
 * Nothing is re-implemented where a real implementation exists. WEVA is
 * this app's own production middleware (middleware/securityMiddleware.js),
 * with in-memory versions of its three storage ports - the same approach as
 * middleware/securityMiddleware.test.js. The fixed-window limiter is the
 * published express-rate-limit package, configured as its documentation
 * describes. Only the account lockout is written here, since it is a
 * policy rather than a library: in a real app it lives in the login
 * controller, which is where afterApp() stands in for it.
 */

const MINUTE = 60 * 1000;

/**
 * @typedef {object} AlgorithmSpec
 * @property {string} id
 * @property {string} label
 * @property {string} summary - One line for the results page.
 * @property {object} config - The settings used, recorded in the results file.
 * @property {() => Promise<{middleware: Function, afterApp?: Function}>} create
 */

/** @type {AlgorithmSpec} */
const weva = {
    id: 'weva',
    label: 'WEVA',
    summary: 'Scores every request: velocity against the device\'s own baseline x endpoint weight x unresolved failures, across device, IP and account.',
    config: {
        source: 'middleware/securityMiddleware.js with in-memory storage ports',
        tuning: 'config/securityConfig.js and core/scorer.js defaults (recorded under environment.weva)'
    },
    async create() {
        // Imported here, after vi.resetModules(): a fresh copy of WEVA's
        // module-level state stores for every run.
        const { createSecurityMiddleware } = await import('../middleware/securityMiddleware.js');
        const { settleDeviceAttempts } = await import('../core/monitor.js');
        const { settleIpAttempts } = await import('../core/ipAttempts.js');
        const { getClientIdentity, normalizeAccount } = await import('../middleware/clientIdentity.js');

        const blocks = new Map();
        const userIds = new Map();
        const middleware = createSecurityMiddleware({
            auditSink: { recordEvaluation: async () => {} },
            ipTrackingStore: {
                async findStatus(id) { return blocks.has(id) ? { ...blocks.get(id) } : null; },
                async block(id, blockedUntil) { blocks.set(id, { isBlocked: true, blockedUntil }); },
                async clear(id) { if (blocks.has(id)) blocks.set(id, { isBlocked: false, blockedUntil: null }); }
            },
            identityResolver: {
                async resolve(email) {
                    if (!userIds.has(email)) userIds.set(email, userIds.size + 1);
                    return { id: userIds.get(email), role: 'admin' };
                }
            }
        });

        return {
            middleware,
            afterApp(req, spec, outcome) {
                if (!outcome.loginSucceeded) return;
                // What controllers/authController.js#completeLogin does on
                // every successful login.
                const { ip, deviceKey } = getClientIdentity(req);
                const account = normalizeAccount(spec.email);
                settleDeviceAttempts(deviceKey, account);
                settleIpAttempts(ip, account);
            }
        };
    }
};

/**
 * express-rate-limit's fixed window, keyed by IP address (its default).
 *
 * `validate: false` switches off the package's start-up checks, which warn
 * a developer about proxy settings from the request headers. They never
 * change a limiting decision, and the simulated requests carry no proxy
 * headers for them to inspect.
 *
 * @param {object} options
 * @returns {Promise<{middleware: Function}>}
 */
async function fixedWindow(options) {
    const { rateLimit } = await import('express-rate-limit');
    return {
        middleware: rateLimit({ ...options, standardHeaders: 'draft-7', legacyHeaders: false, validate: false })
    };
}

/** @type {AlgorithmSpec} */
const fixedWindowStrict = {
    id: 'fw-strict',
    label: 'Fixed window (strict)',
    summary: '5 failed requests per IP per 15 minutes; successful requests are not counted.',
    config: { package: 'express-rate-limit', windowMs: 15 * MINUTE, limit: 5, skipSuccessfulRequests: true, key: 'IP address' },
    create: () => fixedWindow({ windowMs: 15 * MINUTE, limit: 5, skipSuccessfulRequests: true })
};

/** @type {AlgorithmSpec} */
const fixedWindowLenient = {
    id: 'fw-lenient',
    label: 'Fixed window (lenient)',
    summary: '100 requests per IP per 15 minutes, counting every request - the package\'s own README example.',
    config: { package: 'express-rate-limit', windowMs: 15 * MINUTE, limit: 100, skipSuccessfulRequests: false, key: 'IP address' },
    create: () => fixedWindow({ windowMs: 15 * MINUTE, limit: 100 })
};

/** Consecutive failed logins that lock an account. */
const LOCKOUT_THRESHOLD = 3;
/** How long a locked account stays locked. */
const LOCKOUT_MS = 15 * MINUTE;

/** @type {AlgorithmSpec} */
const accountLockout = {
    id: 'lockout',
    label: 'Account lockout',
    summary: '3 consecutive failed logins lock the account for 15 minutes; only sign-in is guarded.',
    config: { threshold: LOCKOUT_THRESHOLD, lockMs: LOCKOUT_MS, key: 'target account', guards: 'POST /api/login only' },
    async create() {
        const { normalizeAccount } = await import('../middleware/clientIdentity.js');
        const accounts = new Map();
        const isLogin = (req) => req.baseUrl + req.route.path === '/api/login';

        return {
            middleware(req, res, next) {
                if (!isLogin(req)) return next();
                const state = accounts.get(normalizeAccount(req.body?.email));
                const left = state?.lockedUntil ? state.lockedUntil - Date.now() : 0;
                if (left > 0) {
                    // Refused before the password is even checked - so the
                    // right password is refused too. That is the lockout.
                    res.setHeader('Retry-After', Math.ceil(left / 1000));
                    return res.status(423).json({ success: false, message: 'Account locked. Try again later.' });
                }
                next();
            },
            afterApp(req, spec, outcome) {
                if (spec.kind !== 'login') return;
                const account = normalizeAccount(spec.email);
                if (outcome.loginSucceeded) {
                    accounts.delete(account);
                    return;
                }
                const state = accounts.get(account) ?? { failures: 0, lockedUntil: 0 };
                state.failures += 1;
                if (state.failures >= LOCKOUT_THRESHOLD) {
                    state.failures = 0;
                    state.lockedUntil = Date.now() + LOCKOUT_MS;
                }
                accounts.set(account, state);
            }
        };
    }
};

/** In the order the results page lists them. */
export const ALGORITHMS = [weva, fixedWindowStrict, fixedWindowLenient, accountLockout];

/** @type {Record<string, AlgorithmSpec>} */
export const ALGORITHM_BY_ID = Object.fromEntries(ALGORITHMS.map(algorithm => [algorithm.id, algorithm]));
