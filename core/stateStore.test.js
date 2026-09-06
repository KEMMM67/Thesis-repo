import { describe, it, expect, afterEach } from 'vitest';
import { MemoryStateStore } from './stateStore.js';

/**
 * @fileoverview Proves MemoryStateStore actually fixes the unbounded-growth
 * problem it was written to fix (see stateStore.js) - not just that it
 * behaves like a plain object for get/set, but that an idle entry is
 * genuinely removed rather than accumulating forever.
 */
describe('MemoryStateStore', () => {
    let store;

    afterEach(() => {
        store?.stopSweeping();
    });

    it('creates a default value on first access and returns the same object on later access', () => {
        store = new MemoryStateStore();
        const first = store.getOrCreate('device-1', () => ({ hits: 0 }));
        first.hits = 5;

        const second = store.getOrCreate('device-1', () => ({ hits: 0 }));

        expect(second).toBe(first);
        expect(second.hits).toBe(5);
        expect(store.size).toBe(1);
    });

    it('set() replaces the stored value outright', () => {
        store = new MemoryStateStore();
        store.getOrCreate('device-1', () => ({ hits: 1 }));

        store.set('device-1', { hits: 99 });

        expect(store.getOrCreate('device-1', () => ({ hits: 0 })).hits).toBe(99);
    });

    it('has() reports whether an entry exists without creating one', () => {
        store = new MemoryStateStore();
        expect(store.has('device-1')).toBe(false);

        store.getOrCreate('device-1', () => ({}));

        expect(store.has('device-1')).toBe(true);
    });

    it('evicts an entry once it has been idle longer than idleTtlMs - the actual memory-leak fix', async () => {
        store = new MemoryStateStore({ idleTtlMs: 30 });
        store.getOrCreate('device-1', () => ({ hits: 1 }));
        expect(store.size).toBe(1);

        await new Promise(resolve => setTimeout(resolve, 100));
        store.evictStale();

        expect(store.size).toBe(0);
        expect(store.has('device-1')).toBe(false);
    });

    it('does not evict an entry that was accessed recently', async () => {
        store = new MemoryStateStore({ idleTtlMs: 200 });
        store.getOrCreate('device-1', () => ({ hits: 1 }));

        await new Promise(resolve => setTimeout(resolve, 50));
        store.getOrCreate('device-1', () => ({ hits: 1 })); // refreshes the idle clock
        store.evictStale();

        expect(store.has('device-1')).toBe(true);
    });
});
