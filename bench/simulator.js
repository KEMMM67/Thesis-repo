import { vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { performance } from 'node:perf_hooks';

/**
 * @fileoverview Discrete-event simulator behind the WEVA comparison
 * (bench/run-comparison.js).
 *
 * A scenario is a cast of actors - attackers and legitimate users - each a
 * script that sends requests over time and reacts to what comes back.
 * simulate() plays one scenario against one algorithm in a world built
 * fresh for that run:
 *
 *   - Simulated time. vitest's fake timers drive the clock, so thirty
 *     simulated minutes take milliseconds and every run starts at the same
 *     instant. Faking timers, not just overriding Date.now, matters: core/
 *     mitigation.js reads `new Date()`, which a Date.now override never
 *     reaches, and express-rate-limit and WEVA's state stores clean up on
 *     setInterval, which only fires when the fake clock is advanced.
 *
 *   - Fresh modules. WEVA keeps its per-device history, per-IP attempt
 *     windows and EMA baselines in module-level stores (core/monitor.js,
 *     core/profiler.js, core/ipAttempts.js). vi.resetModules() before every
 *     run means each algorithm imports brand-new copies, so no run inherits
 *     another run's attackers. express-rate-limit and the lockout baseline
 *     get a new store per run for the same reason.
 *
 *   - The same random numbers. Every run of a scenario uses the same seed,
 *     so all four algorithms face exactly the same students, typos and
 *     arrival times; the algorithm is the only thing that changes.
 *
 * Each request goes through the algorithm's real Express middleware, using
 * an in-memory request and response, then - if it was let through - through
 * a stand-in for the application: a password check that succeeds or fails,
 * or a record update that succeeds. Nothing here touches a database (see
 * bench/run-comparison.js for the guard that enforces that).
 */

/** Simulated wall-clock time at the start of every run: 2026-10-06 08:00 in Manila. */
export const SIM_EPOCH = Date.UTC(2026, 9, 6, 0, 0, 0);

/** Seed shared by every run unless a caller passes its own. */
export const DEFAULT_SEED = 20261006;

/**
 * Timer APIs the fake clock replaces. setImmediate is deliberately left
 * real: flush() below uses it to let pending promise callbacks run between
 * simulated instants without moving the clock.
 */
const FAKED_TIMERS = ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'];

/**
 * A small seeded random-number generator (mulberry32). Math.random cannot
 * be seeded, and the comparison is only fair if every algorithm sees the
 * same random draws.
 *
 * @param {number} seed
 * @returns {() => number} Returns floats in [0, 1).
 */
export function seededRandom(seed) {
    let state = seed >>> 0;
    return () => {
        state = (state + 0x6D2B79F5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

/**
 * Just enough of an Express response for the middleware under test:
 * status, headers, a body, and the 'finish' event express-rate-limit
 * waits for before it decides whether to un-count a request
 * (skipSuccessfulRequests).
 */
export class FakeResponse extends EventEmitter {
    constructor() {
        super();
        this.statusCode = 200;
        this.headers = {};
        this.body = undefined;
        this.headersSent = false;
        this.writableEnded = false;
    }

    status(code) {
        this.statusCode = code;
        return this;
    }

    setHeader(name, value) {
        this.headers[name.toLowerCase()] = String(value);
    }

    getHeader(name) {
        return this.headers[name.toLowerCase()];
    }

    json(body) {
        return this.send(body);
    }

    send(body) {
        this.body = body;
        this.headersSent = true;
        this.writableEnded = true;
        this.emit('finish');
        return this;
    }
}

/**
 * Builds the Express request a request spec stands for, shaped exactly as
 * the real routes present it to middleware: POST /api/login comes through
 * routes/authRoutes.js's router (baseUrl "/api", route "/login"); admin
 * routes are registered on the app (baseUrl "", the full route pattern).
 *
 * @param {object} spec - From a scenario actor (see bench/scenarios.js).
 * @returns {object}
 */
function toExpressRequest(spec) {
    const headers = spec.deviceId ? { 'x-device-id': spec.deviceId } : {};
    if (spec.kind === 'login') {
        return {
            method: 'POST', baseUrl: '/api', path: '/login', originalUrl: '/api/login', route: { path: '/login' },
            ip: spec.ip, headers,
            body: { email: spec.email, password: spec.correctPassword ? 'the-right-password' : 'a-wrong-guess' }
        };
    }
    return {
        method: spec.method, baseUrl: '', path: spec.path, originalUrl: spec.path, route: { path: spec.route },
        ip: spec.ip, headers, body: {},
        user: { email: spec.actorEmail, role: spec.role }
    };
}

/**
 * The application behind the guard, reduced to what decides an outcome: a
 * login succeeds only with the right password; any admin request that gets
 * this far succeeds.
 *
 * @param {object} spec
 * @returns {{status: number, loginSucceeded?: boolean}}
 */
function application(spec) {
    if (spec.kind === 'login') {
        return spec.correctPassword ? { status: 200, loginSucceeded: true } : { status: 401, loginSucceeded: false };
    }
    return { status: 200 };
}

/**
 * Runs an Express middleware to completion.
 *
 * @returns {Promise<boolean>} true if it called next() (the request was let
 *          through), false if it answered the request itself (refused it).
 */
function runMiddleware(middleware, req, res) {
    return new Promise((resolve, reject) => {
        const answered = () => resolve(false);
        res.once('finish', answered);
        const next = (err) => {
            res.off('finish', answered);
            if (err) reject(err);
            else resolve(true);
        };
        try {
            Promise.resolve(middleware(req, res, next)).catch(reject);
        } catch (err) {
            reject(err);
        }
    });
}

/**
 * How long a refusal told the client to wait, from whichever place the
 * algorithm puts it: WEVA's BLOCK body (retryAfterSeconds), WEVA's
 * THROTTLE body (retryAfter), or a Retry-After header (express-rate-limit,
 * the lockout baseline).
 *
 * @param {FakeResponse} res
 * @returns {number|null} Milliseconds, or null if the refusal gave none.
 */
function retryAfterMs(res) {
    const body = typeof res.body === 'object' && res.body !== null ? res.body : {};
    const seconds = body.retryAfterSeconds ?? body.retryAfter ?? Number(res.getHeader('retry-after'));
    return Number.isFinite(seconds) ? seconds * 1000 : null;
}

/** Lets every pending promise callback run, without moving the fake clock. */
const flush = () => new Promise(resolve => setImmediate(resolve));

/**
 * Inserts a scheduled actor step, keeping the queue ordered by time and,
 * at the same time, by the order steps were scheduled - so simultaneous
 * requests always start in the same order, run after run.
 */
function enqueue(queue, entry) {
    let lo = 0;
    let hi = queue.length;
    while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        const other = queue[mid];
        if (other.at < entry.at || (other.at === entry.at && other.seq < entry.seq)) lo = mid + 1;
        else hi = mid;
    }
    queue.splice(lo, 0, entry);
}

/**
 * Plays one scenario against one algorithm in a fresh world (see this
 * file's @fileoverview).
 *
 * @param {object} scenario - From bench/scenarios.js.
 * @param {object} algorithmSpec - From bench/algorithms.js.
 * @param {object} [options]
 * @param {object} [options.params] - Overrides scenario.params (e.g. a campus size for the sweep).
 * @param {number} [options.seed]
 * @returns {Promise<{records: object[], cast: object[], durationMs: number, guardMicros: number[]}>}
 *          `records` holds one entry per request, in the order they were decided.
 */
export async function simulate(scenario, algorithmSpec, { params = {}, seed = DEFAULT_SEED } = {}) {
    // The comparison always measures WEVA's shipped tuning. A SECURITY_*
    // variable left in the shell would silently change the thresholds
    // config/securityConfig.js reads at import time.
    for (const key of Object.keys(process.env)) {
        if (key.startsWith('SECURITY_')) delete process.env[key];
    }

    vi.useFakeTimers({ now: SIM_EPOCH, toFake: FAKED_TIMERS });
    vi.resetModules();
    // WEVA logs one line per scored request; thousands of them would bury the results.
    const quiet = vi.spyOn(console, 'log').mockImplementation(() => {});

    try {
        const algorithm = await algorithmSpec.create();
        let now = 0;
        const clock = { now: () => now };
        const cast = scenario.cast({ ...scenario.params, ...params }, seededRandom(seed), clock);

        const records = [];
        const guardMicros = [];
        const queue = [];
        let seq = 0;

        const schedule = (actorIndex, step) => {
            if (!step.done) enqueue(queue, { at: now + step.value.after, seq: seq++, actorIndex, requests: step.value.send });
        };
        cast.forEach((actor, index) => {
            actor.iterator = actor.script();
            schedule(index, actor.iterator.next());
        });

        // Simultaneous requests can finish in a different order than they
        // started; records are kept in start order, so "the 3rd request of
        // a burst" means the 3rd one sent.
        let started = 0;
        const execute = async (spec, actorIndex) => {
            const order = started++;
            const req = toExpressRequest(spec);
            const res = new FakeResponse();
            const startedAt = performance.now();
            const letThrough = await runMiddleware(algorithm.middleware, req, res);
            guardMicros.push((performance.now() - startedAt) * 1000);

            let result;
            if (!letThrough) {
                result = { reached: false, status: res.statusCode, retryAfterMs: retryAfterMs(res) };
            } else {
                const outcome = application(spec);
                // In the real app the login controller settles WEVA's attempt
                // history before it answers (controllers/authController.js
                // #completeLogin); the lockout baseline counts failures here.
                algorithm.afterApp?.(req, spec, outcome);
                res.status(outcome.status).json({});
                result = { reached: true, status: outcome.status, retryAfterMs: null };
            }
            records.push({ order, t: now, actor: actorIndex, role: cast[actorIndex].role, ...result });
            return result;
        };

        while (queue.length) {
            const at = queue[0].at;
            if (at > now) {
                vi.advanceTimersByTime(at - now);
                now = at;
            }
            const group = [];
            while (queue.length && queue[0].at === at) group.push(queue.shift());

            // Everything due at this instant is sent at the same simulated
            // moment, but - as separate HTTP requests are in Node - each one
            // starts in its own event-loop turn. Started in a single turn
            // instead, their promise callbacks interleave in a way a real
            // server never produces: express-rate-limit's MemoryStore hands
            // back its live counter, so ten requests started together all
            // read the tenth increment and were all refused, the first one
            // included.
            const pending = group.map(entry => entry.requests.map(() => null));
            for (let g = 0; g < group.length; g++) {
                for (let r = 0; r < group[g].requests.length; r++) {
                    pending[g][r] = execute(group[g].requests[r], group[g].actorIndex);
                    await flush();
                }
            }
            const results = await Promise.all(pending.map(requests => Promise.all(requests)));
            await flush();
            group.forEach((entry, i) => schedule(entry.actorIndex, cast[entry.actorIndex].iterator.next(results[i])));
        }

        records.sort((a, b) => a.order - b.order);
        return { records, cast, durationMs: now, guardMicros };
    } finally {
        quiet.mockRestore();
        vi.clearAllTimers();
        vi.useRealTimers();
    }
}

/**
 * Reduces one run to the numbers the comparison reports.
 *
 * Attack side: how many attack requests were sent, how many got through
 * (reached the password check, or executed a destructive change), and
 * when the first one was refused.
 *
 * Legitimate side: how many legitimate requests were refused, how many
 * users were refused at least once, and how many were denied outright -
 * never finished what they came to do (sign in, or save every grade)
 * before giving up. A user who got through after waiting is "delayed",
 * and the worst such delay is reported too.
 *
 * @param {{records: object[], cast: object[]}} run
 * @returns {{attack: object|null, legit: object|null}}
 */
export function summarize({ records, cast }) {
    const attack = records.filter(r => r.role === 'attack');
    const legit = records.filter(r => r.role === 'legit');
    const firstRefused = attack.findIndex(r => !r.reached);
    const firstHardBlock = attack.findIndex(r => !r.reached && r.status !== 429);
    const users = cast.filter(actor => actor.role === 'legit');
    const delays = users
        .filter(user => user.report.refusals > 0 && user.report.achieved === user.report.goal)
        .map(user => (user.report.finishedAt - user.report.startedAt) / 1000);

    return {
        attack: attack.length === 0 ? null : {
            sent: attack.length,
            reached: attack.filter(r => r.reached).length,
            refused: attack.filter(r => !r.reached).length,
            firstRefusedAttempt: firstRefused === -1 ? null : firstRefused + 1,
            firstRefusedAtSeconds: firstRefused === -1 ? null : attack[firstRefused].t / 1000,
            firstBlockAttempt: firstHardBlock === -1 ? null : firstHardBlock + 1
        },
        legit: users.length === 0 ? null : {
            users: users.length,
            requests: legit.length,
            refused: legit.filter(r => !r.reached).length,
            usersRefused: users.filter(user => user.report.refusals > 0).length,
            usersDenied: users.filter(user => user.report.achieved < user.report.goal).length,
            worstDelaySeconds: delays.length ? Math.max(...delays) : 0
        }
    };
}
