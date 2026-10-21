/**
 * @fileoverview The behavioral history WEVA scores against, ported from the
 * thesis build's core/monitor.js (request timestamps and the failed-login
 * ledger), core/profiler.js (EMA baseline), core/ipAttempts.js (the 30 s IP
 * window) and core/stateStore.js (idle eviction).
 *
 * Kept per middleware instance and in memory, as the thesis build keeps it.
 * Several server processes would each have their own; sharing it would mean
 * moving it to a store such as Redis.
 */

const IDLE_TTL_MS = 30 * 60 * 1000;    // forget a client after 30 idle minutes
const SWEEP_EVERY_MS = 5 * 60 * 1000;

/**
 * A get-or-create map that drops entries left idle for 30 minutes, so a
 * stream of new device IDs cannot grow it without bound. Swept on access
 * rather than on a timer, so it holds no process open.
 */
class IdleStore {
    #entries = new Map();
    #lastSweep = Date.now();

    getOrCreate(key, createDefault) {
        const now = Date.now();
        if (now - this.#lastSweep >= SWEEP_EVERY_MS) this.#sweep(now);

        let entry = this.#entries.get(key);
        if (!entry) {
            entry = { value: createDefault(), lastAccessed: now };
            this.#entries.set(key, entry);
        }
        entry.lastAccessed = now;
        return entry.value;
    }

    has(key) {
        return this.#entries.has(key);
    }

    #sweep(now) {
        this.#lastSweep = now;
        for (const [key, entry] of this.#entries) {
            if (now - entry.lastAccessed > IDLE_TTL_MS) this.#entries.delete(key);
        }
    }
}

/**
 * Per-client history, keyed by device ID (or by IP for a client that sends
 * none): request times inside the window, failed logins not yet settled, and
 * the learned baseline velocity.
 */
export class DeviceTracker {
    #store = new IdleStore();

    /** @param {{windowMs: number, emaAlpha: number}} config */
    constructor({ windowMs, emaAlpha }) {
        this.windowMs = windowMs;
        this.emaAlpha = emaAlpha;
    }

    #state(key) {
        return this.#store.getOrCreate(key, () => ({ requests: [], attemptsByAccount: new Map(), baselineRate: 0 }));
    }

    /**
     * The client's current features for computeScore(). Velocity is the
     * requests inside the window divided by the time since the first of
     * them, in req/s. A span under 1 ms counts as 1 ms, so two earlier
     * requests in the same millisecond read as 2000 req/s rather than a
     * false 0.
     *
     * `loginAttempts` adds up every unsettled attempt, whichever account it
     * targeted: failing once at each of three accounts (password spraying)
     * is as suspicious as failing three times at one.
     *
     * @param {string} key
     * @param {string} endpoint
     * @returns {{requestRate: number, loginAttempts: number, endpoint: string}}
     */
    features(key, endpoint) {
        const now = Date.now();
        const state = this.#state(key);
        state.requests = state.requests.filter(time => now - time < this.windowMs);

        let requestRate = 0;
        if (state.requests.length > 1) {
            requestRate = (state.requests.length / Math.max(now - state.requests[0], 1)) * 1000;
        }

        let loginAttempts = 0;
        for (const count of state.attemptsByAccount.values()) loginAttempts += count;

        return { requestRate, loginAttempts, endpoint };
    }

    /** @returns {{requestRate: number}} */
    baseline(key) {
        return { requestRate: this.#state(key).baselineRate };
    }

    recordRequest(key) {
        this.#state(key).requests.push(Date.now());
    }

    /** Puts one login attempt on the ledger, under the account it targeted. */
    recordAttempt(key, account) {
        const ledger = this.#state(key).attemptsByAccount;
        ledger.set(account, (ledger.get(account) || 0) + 1);
    }

    /**
     * Exponential moving average: the baseline drifts toward the client's
     * real habits, and alpha 0.1 keeps one outlier from moving it far.
     */
    learn(key, features) {
        const state = this.#state(key);
        state.baselineRate = features.requestRate * this.emaAlpha + state.baselineRate * (1 - this.emaAlpha);
    }

    /**
     * After a successful login to `account`: the attempts aimed at that
     * account come off the ledger and the velocity window restarts. Attempts
     * at other accounts stay, so signing into your own account cannot wipe
     * your guesses at someone else's.
     */
    settle(key, account) {
        if (!this.#store.has(key)) return;
        const state = this.#state(key);
        state.requests = [];
        state.attemptsByAccount.delete(account);
    }
}

/**
 * Login attempts per IP inside the window (30 s by default). It catches a bot
 * that sends a new device ID with every guess: each fake device starts clean,
 * but every guess lands on one address. It forgets after 30 s because an IP is
 * shared - a whole campus can sit behind one NAT address.
 */
export class IpAttemptWindow {
    #store = new IdleStore();

    /** @param {{windowMs: number}} config */
    constructor({ windowMs }) {
        this.windowMs = windowMs;
    }

    #recent(ip, now) {
        const entry = this.#store.getOrCreate(ip, () => ({ attempts: [] }));
        entry.attempts = entry.attempts.filter(attempt => now - attempt.time < this.windowMs);
        return entry.attempts;
    }

    count(ip) {
        return this.#recent(ip, Date.now()).length;
    }

    record(ip, account) {
        const now = Date.now();
        this.#recent(ip, now).push({ time: now, account });
    }

    /** After a successful login to `account` from this IP: settles only that account's attempts. */
    settle(ip, account) {
        if (!this.#store.has(ip)) return;
        const entry = this.#store.getOrCreate(ip, () => ({ attempts: [] }));
        entry.attempts = entry.attempts.filter(attempt => attempt.account !== account);
    }
}
