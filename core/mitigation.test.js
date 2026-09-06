import { describe, it, expect, beforeEach } from 'vitest';
import { applyMitigation } from './mitigation.js';

/**
 * @fileoverview Proves core/mitigation.js needs no real database - a fake,
 * in-memory IpTrackingStore (implementing exactly the three methods
 * core/ports.js#IpTrackingStore declares) is enough to exercise every
 * branch of applyMitigation(). This is the concrete evidence for the
 * Hexagonal Architecture refactor's actual claim: this file no longer
 * imports Prisma, and this test never touches Postgres to prove it.
 */

function createFakeIpTrackingStore() {
    const rows = new Map();
    return {
        async findStatus(id) {
            return rows.has(id) ? { ...rows.get(id) } : null;
        },
        async block(id, blockedUntil) {
            rows.set(id, { isBlocked: true, blockedUntil });
        },
        async clear(id) {
            if (rows.has(id)) rows.set(id, { isBlocked: false, blockedUntil: null });
        },
        _rows: rows
    };
}

function createFakeResponse() {
    return {
        statusCode: null,
        body: null,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; }
    };
}

describe('applyMitigation (fake IpTrackingStore, zero database)', () => {
    let store;
    let res;

    beforeEach(() => {
        store = createFakeIpTrackingStore();
        res = createFakeResponse();
    });

    it('BLOCKs and persists the block via the injected store', async () => {
        const terminated = await applyMitigation('BLOCK', res, 'device-1', store);

        expect(terminated).toBe(true);
        expect(res.statusCode).toBe(403);
        expect(res.body.success).toBe(false);

        // retryAfterSeconds lets the frontend run a real countdown instead
        // of guessing a fixed duration (see core/mitigation.js#sendBlockedResponse).
        // Asserted as "a positive number", not a hardcoded 60, so this test
        // stays correct regardless of how SECURITY_MITIGATION_BLOCK_MS is tuned.
        expect(res.body.retryAfterSeconds).toBeGreaterThan(0);

        const status = await store.findStatus('device-1');
        expect(status.isBlocked).toBe(true);
        expect(status.blockedUntil).toBeInstanceOf(Date);
    });

    it('THROTTLEs without touching the store', async () => {
        const terminated = await applyMitigation('THROTTLE', res, 'device-2', store);

        expect(terminated).toBe(true);
        expect(res.statusCode).toBe(429);
        expect(await store.findStatus('device-2')).toBeNull();
    });

    it('ALLOWs a device with no tracked history', async () => {
        const terminated = await applyMitigation('ALLOW', res, 'device-3', store);

        expect(terminated).toBe(false);
        expect(res.statusCode).toBeNull();
    });

    it('rejects a request even on an ALLOW-scored request, if the device has an active prior block', async () => {
        await applyMitigation('BLOCK', res, 'device-4', store); // establishes the block
        const res2 = createFakeResponse();

        const terminated = await applyMitigation('ALLOW', res2, 'device-4', store);

        expect(terminated).toBe(true);
        expect(res2.statusCode).toBe(403);
        // The "already blocked" fast path reports the lockout's real
        // remaining time too, not just the fresh-BLOCK path above.
        expect(res2.body.retryAfterSeconds).toBeGreaterThan(0);
    });

    it('clears a stale (expired) block when a later request comes through', async () => {
        // Manually seed an already-expired block, bypassing block() so the
        // expiry is in the past rather than governed by
        // securityConfig.mitigation.temporaryBlockMs.
        store._rows.set('device-5', { isBlocked: true, blockedUntil: new Date(Date.now() - 1000) });

        const terminated = await applyMitigation('ALLOW', res, 'device-5', store);

        expect(terminated).toBe(false);
        const status = await store.findStatus('device-5');
        expect(status.isBlocked).toBe(false);
        expect(status.blockedUntil).toBeNull();
    });
});
