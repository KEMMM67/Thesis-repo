import { describe, it, expect, vi } from 'vitest';
import { createSecurityMiddleware } from './securityMiddleware.js';

/**
 * @fileoverview Drives the full WEVA request pipeline (identity -> features
 * -> score -> decision -> mitigation) with in-memory fake adapters, no
 * database. Covers the two pipeline-level fixes: simultaneous requests are
 * scored against each other (race condition), and a bot cannot reset its
 * failure history by rotating its client-supplied x-device-id (IP layer).
 */

let seq = 0;
const uniqueId = (prefix) => `${prefix}-${Date.now().toString(36)}-${++seq}`;
const uniqueIp = () => `198.51.${Math.floor(++seq / 250) % 250}.${(seq % 250) + 1}`;

function fakeIpTrackingStore() {
    const rows = new Map();
    return {
        async findStatus(id) { return rows.has(id) ? { ...rows.get(id) } : null; },
        async block(id, blockedUntil) { rows.set(id, { isBlocked: true, blockedUntil }); },
        async clear(id) { if (rows.has(id)) rows.set(id, { isBlocked: false, blockedUntil: null }); },
        rows
    };
}

function buildMiddleware(store = fakeIpTrackingStore()) {
    const middleware = createSecurityMiddleware({
        auditSink: { recordEvaluation: async () => {} },
        ipTrackingStore: store,
        identityResolver: { resolve: async () => null }
    });
    return { middleware, store };
}

function loginRequest({ deviceId, ip }) {
    return { headers: deviceId ? { 'x-device-id': deviceId } : {}, ip, baseUrl: '/api', path: '/login', body: {} };
}

async function send(middleware, req) {
    const res = {
        statusCode: null,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; }
    };
    let passed = false;
    await middleware(req, res, () => { passed = true; });
    return { passed, status: res.statusCode };
}

describe('securityMiddleware - simultaneous requests (race condition)', () => {
    it('scores a 20-request burst from one device against itself: only 2 reach the password check', async () => {
        const { middleware } = buildMiddleware();
        const deviceId = uniqueId('burst');
        const ip = uniqueIp();

        // All 20 calls start in the same tick, like parallel connections
        // arriving together. Before the fix each one read the device's
        // history before any of the others had recorded itself, so all 20
        // scored 0 (ALLOW) and all 20 reached bcrypt.
        const results = await Promise.all(
            Array.from({ length: 20 }, () => send(middleware, loginRequest({ deviceId, ip })))
        );

        expect(results.filter(r => r.passed)).toHaveLength(2);
        expect(results.filter(r => r.status === 403)).toHaveLength(18);
    });
});

describe('securityMiddleware - IP layer', () => {
    it('blocks the IP itself when a bot uses a new x-device-id on every attempt', async () => {
        const { middleware, store } = buildMiddleware();
        const ip = uniqueIp();

        const outcomes = [];
        for (let i = 0; i < 9; i++) {
            outcomes.push(await send(middleware, loginRequest({ deviceId: uniqueId('rotating'), ip })));
        }

        // Same 4 / 3 / BLOCK ladder a single device gets - rotating IDs buys nothing.
        expect(outcomes.map(o => o.passed)).toEqual([true, true, true, true, false, false, false, false, false]);
        expect(outcomes.slice(4, 7).map(o => o.status)).toEqual([429, 429, 429]);
        expect(outcomes[7].status).toBe(403);
        expect(store.rows.get(ip)?.isBlocked).toBe(true);

        // A 9th, never-seen device ID from the same IP is still refused.
        expect(outcomes[8].status).toBe(403);
    });

    it('keeps the per-device ladder for one paced device, blocking the device rather than its IP', async () => {
        const { middleware, store } = buildMiddleware();
        const deviceId = uniqueId('paced');
        const ip = uniqueIp();

        vi.useFakeTimers({ toFake: ['Date'] });
        try {
            let now = Date.parse('2026-09-24T00:00:00Z');
            const outcomes = [];
            for (let i = 0; i < 8; i++) {
                vi.setSystemTime(now);
                outcomes.push(await send(middleware, loginRequest({ deviceId, ip })));
                now += 600; // one attempt every 0.6 s - below the velocity floor
            }

            expect(outcomes.map(o => o.passed)).toEqual([true, true, true, true, false, false, false, false]);
            expect(outcomes[7].status).toBe(403);
            expect(store.rows.get(deviceId)?.isBlocked).toBe(true);
            expect(store.rows.has(ip)).toBe(false);
        } finally {
            vi.useRealTimers();
        }
    });

    it('never applies an IP block to an authenticated request', async () => {
        const { middleware, store } = buildMiddleware();
        const ip = uniqueIp();
        store.rows.set(ip, { isBlocked: true, blockedUntil: new Date(Date.now() + 60_000) });

        const result = await send(middleware, {
            headers: { 'x-device-id': uniqueId('admin') },
            ip,
            baseUrl: '',
            path: '/api/admin/logs',
            body: {},
            user: { email: 'admin@example.edu.ph', role: 'admin' }
        });

        expect(result.passed).toBe(true);
    });
});
