/**
 * @fileoverview Generic in-memory keyed store with idle-eviction.
 *
 * core/monitor.js and core/profiler.js used to hold their per-device
 * behavioral state directly in bare module-level objects (`activeUsers`,
 * `baselines`). Those objects grew by one entry for every distinct
 * device/IP ever seen and never removed one, for the entire lifetime of
 * the process - a genuine unbounded-memory-growth bug, not just a style
 * complaint. MemoryStateStore fixes that: an entry is evicted once it has
 * gone unused for `idleTtlMs`, while preserving the exact "get the
 * existing value, or create and store a default" access pattern both
 * modules already relied on, so neither needed to change how it reads or
 * writes its state - only where that state physically lives.
 *
 * This class is also deliberately generic - it knows nothing about
 * requests, login attempts, or EMA baselines; callers supply their own
 * default shape via `createDefault`. That is what makes it the seam
 * described in the modularization roadmap: a `RedisStateStore`
 * implementing the same conceptual contract (get-or-create, set, has)
 * would let WEVA's behavioral state survive a restart and stay correct
 * across more than one server process, without core/monitor.js or
 * core/profiler.js needing to know which one is backing them - the same
 * reasoning core/mitigation.js already applied when it chose to persist
 * `ipTracking` in the database instead of an in-memory map.
 *
 * One honest caveat for that future step: every method here is
 * synchronous because in-process memory access is synchronous. A
 * Redis-backed implementation of this same contract would need `get`/
 * `getOrCreate`/`set` to return Promises, since talking to Redis is I/O -
 * which means core/monitor.js and core/profiler.js would need to become
 * `async` at that point too. That is a known, deliberate follow-up, not a
 * hidden gotcha this class is pretending not to have.
 */

/**
 * Default idle window before an entry is evicted: 30 minutes. Long enough
 * that a real session's baseline survives a normal pause between requests;
 * short enough that a device which never comes back does not live in
 * memory forever.
 */
const DEFAULT_IDLE_TTL_MS = 30 * 60 * 1000;

/** Default interval between background sweeps for stale entries. */
const DEFAULT_SWEEP_INTERVAL_MS = 5 * 60 * 1000;

export class MemoryStateStore {
    /**
     * @param {object} [options]
     * @param {number} [options.idleTtlMs] - How long an entry may sit unused before evictStale() removes it.
     * @param {number} [options.sweepIntervalMs] - How often the background sweep runs.
     */
    constructor({ idleTtlMs = DEFAULT_IDLE_TTL_MS, sweepIntervalMs = DEFAULT_SWEEP_INTERVAL_MS } = {}) {
        /** @type {Map<string, {value: object, lastAccessed: number}>} */
        this.entries = new Map();
        this.idleTtlMs = idleTtlMs;

        // unref() so this timer never keeps the Node process alive on its
        // own - a short-lived script or a test run should still be able to
        // exit cleanly without an explicit stopSweeping() call.
        this.sweepTimer = setInterval(() => this.evictStale(), sweepIntervalMs);
        this.sweepTimer.unref?.();
    }

    /**
     * Returns the value stored under `key`, creating it via `createDefault`
     * on first access. Every access - read or create - refreshes the
     * entry's idle clock, so a device that keeps making requests is never
     * evicted out from under itself.
     *
     * @param {string} key
     * @param {() => object} createDefault
     * @returns {object}
     */
    getOrCreate(key, createDefault) {
        const existing = this.entries.get(key);
        if (existing) {
            existing.lastAccessed = Date.now();
            return existing.value;
        }
        const value = createDefault();
        this.entries.set(key, { value, lastAccessed: Date.now() });
        return value;
    }

    /**
     * Replaces the value stored under `key` outright, refreshing its idle
     * clock. Part of the store's generic get/set contract (the one a
     * Redis-backed store would implement too); WEVA's own modules currently
     * update their entries in place through getOrCreate() instead.
     *
     * @param {string} key
     * @param {object} value
     * @returns {void}
     */
    set(key, value) {
        this.entries.set(key, { value, lastAccessed: Date.now() });
    }

    /**
     * @param {string} key
     * @returns {boolean} Whether an entry currently exists for `key`. Does
     *          not count as an access - it does not refresh the entry's
     *          idle clock.
     */
    has(key) {
        return this.entries.has(key);
    }

    /**
     * Removes every entry that has not been accessed within `idleTtlMs`.
     * Runs automatically on a timer (see constructor); exposed publicly so
     * tests can assert eviction happens without waiting on the real
     * background interval.
     *
     * @returns {number} Number of entries evicted.
     */
    evictStale() {
        const cutoff = Date.now() - this.idleTtlMs;
        let evicted = 0;
        for (const [key, entry] of this.entries) {
            if (entry.lastAccessed < cutoff) {
                this.entries.delete(key);
                evicted++;
            }
        }
        return evicted;
    }

    /** @returns {number} Current number of tracked entries - exposed for diagnostics/tests. */
    get size() {
        return this.entries.size;
    }

    /** Stops the background sweep timer. Call on graceful shutdown or in test teardown. */
    stopSweeping() {
        clearInterval(this.sweepTimer);
    }
}
