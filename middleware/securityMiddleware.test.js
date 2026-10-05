import { describe, it, expect, vi } from 'vitest';
import { createSecurityMiddleware, readVerdict } from './securityMiddleware.js';
import { settleDeviceAttempts } from '../core/monitor.js';
import { settleIpAttempts, countRecentAttempts } from '../core/ipAttempts.js';

/**
 * @fileoverview Drives the full WEVA request pipeline (identity -> features
 * -> score -> decision -> mitigation) with in-memory fake adapters, no
 * database. Covers the pipeline-level fixes: simultaneous requests are
 * scored against each other (race condition); a bot cannot reset its
 * failure history by rotating its client-supplied x-device-id (IP layer
 * before login, account layer after); logging into your own account does
 * not reset guesses at someone else's; throttled/blocked traffic is never
 * learned as normal; and endpoint weights come from the matched route.
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

function buildMiddleware(store = fakeIpTrackingStore(), { resolve = async () => null } = {}) {
    const audits = [];
    const middleware = createSecurityMiddleware({
        auditSink: { recordEvaluation: async (evaluation) => { audits.push(evaluation); } },
        ipTrackingStore: store,
        identityResolver: { resolve }
    });
    return { middleware, store, audits };
}

function loginRequest({ deviceId, ip, email }) {
    return {
        headers: deviceId ? { 'x-device-id': deviceId } : {}, ip, method: 'POST',
        baseUrl: '/api', path: '/login', route: { path: '/login' },
        body: email ? { email } : {}
    };
}

/** A signed-in admin's DELETE /api/students/:id, on a bulk-seeded student ID. */
function adminDelete({ deviceId, ip, email = 'admin@x.edu.ph' }) {
    return {
        headers: { 'x-device-id': deviceId }, ip, body: {}, method: 'DELETE',
        baseUrl: '', path: '/api/students/CC25-000001', route: { path: '/api/students/:id' },
        user: { email, role: 'admin' }
    };
}

/** Runs `fn` with Date faked, handing it a function that advances the clock. */
async function withClock(fn) {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
        let now = Date.parse('2026-09-24T03:00:00Z');
        // Set before `fn` runs, so a request sent before the first advance
        // is stamped at the start time - not at the real current date,
        // which lies ahead of every simulated time and would never age out.
        vi.setSystemTime(now);
        await fn((ms) => { now += ms; vi.setSystemTime(now); });
    } finally {
        vi.useRealTimers();
    }
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
    it('throttles the IP itself when a bot uses a new x-device-id on every attempt: 4 guesses per 30 s, never a block', async () => {
        const { middleware, store } = buildMiddleware();
        const ip = uniqueIp();
        const outcomes = [];
        const later = [];

        await withClock(async (advance) => {
            for (let i = 0; i < 9; i++) {
                outcomes.push(await send(middleware, loginRequest({ deviceId: uniqueId('rotating'), ip })));
                advance(1000);
            }
            // 30.5 s after the first guess it has left the window; the 5
            // refused guesses were never recorded, so exactly one more gets
            // through - and the next is throttled behind it.
            advance(21500);
            later.push(await send(middleware, loginRequest({ deviceId: uniqueId('rotating'), ip })));
            advance(100);
            later.push(await send(middleware, loginRequest({ deviceId: uniqueId('rotating'), ip })));
        });

        // The same 4 password checks a single device gets before THROTTLE...
        expect(outcomes.map(o => o.passed)).toEqual([true, true, true, true, false, false, false, false, false]);
        expect(outcomes.slice(4).map(o => o.status)).toEqual([429, 429, 429, 429, 429]);
        // ...but the IP layer stops at THROTTLE: refused guesses are not
        // recorded, so its window never reaches BLOCK, and nothing is stored.
        expect(store.rows.has(ip)).toBe(false);
        expect(later.map(o => o.passed)).toEqual([true, false]);
        expect(later[1].status).toBe(429);
    });

    it('does not count refused attempts at the IP, so a busy shared address recovers instead of locking itself out', async () => {
        const { middleware } = buildMiddleware();
        const ip = uniqueIp();
        const refused = [];
        let windowAtThrottle;
        let windowAfter;

        await withClock(async (advance) => {
            // Four students on one campus IP mistype within a few seconds:
            // the IP window reaches THROTTLE.
            for (let i = 0; i < 4; i++) {
                await send(middleware, loginRequest({ deviceId: uniqueId('typo'), ip, email: `typo${i}@x.edu.ph` }));
                advance(500);
            }
            // Thirty more students arrive over the next 24 s and are throttled.
            for (let i = 0; i < 30; i++) {
                refused.push(await send(middleware, loginRequest({ deviceId: uniqueId('arrival'), ip, email: `s${i}@x.edu.ph` })));
                advance(800);
            }
            windowAtThrottle = countRecentAttempts(ip);
            // Once the four typos are 30 s old the window is empty again -
            // none of the 30 refusals were recorded to keep it full.
            advance(6000);
            windowAfter = countRecentAttempts(ip);
        });
        expect(refused.every(o => o.status === 429)).toBe(true);
        expect(windowAtThrottle).toBe(4);
        expect(windowAfter).toBe(0);
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

describe('securityMiddleware - own-account logins between guesses (#1)', () => {
    /** What controllers/authController.js#completeLogin does after a successful login. */
    const loginSucceeded = (deviceId, ip, email) => {
        settleDeviceAttempts(deviceId, email);
        settleIpAttempts(ip, email);
    };

    /** 30 guesses at a victim, with a login to the attacker's own account after every 3rd. */
    async function ownAccountAttack({ rotate }) {
        const { middleware } = buildMiddleware();
        const fixedDevice = uniqueId('own-account');
        const ip = uniqueIp();
        let victimChecks = 0;
        await withClock(async (advance) => {
            for (let i = 0; i < 40; i++) {
                advance(2000);
                const own = i % 4 === 3;
                const email = own ? 'attacker@x.edu.ph' : 'victim@x.edu.ph';
                const deviceId = rotate ? uniqueId('rotating') : fixedDevice;
                const { passed } = await send(middleware, loginRequest({ deviceId, ip, email }));
                if (passed && own) loginSucceeded(deviceId, ip, email);
                if (passed && !own) victimChecks++;
            }
        });
        return victimChecks;
    }

    it('keeps counting guesses at the victim from one device (was 30 of 30 reaching the password check)', async () => {
        expect(await ownAccountAttack({ rotate: false })).toBe(4);
    });

    it('keeps counting them at the IP when the device ID rotates too (was 30 of 30)', async () => {
        // The IP layer allows 4 password checks per 30 s window and the
        // attack runs for 80 s: 12. The logins to the attacker's own account
        // settle none of the victim's - with whole-window settling, all 30
        // guesses reached the password check.
        expect(await ownAccountAttack({ rotate: true })).toBe(12);
    });

    it('still gives the next student on a shared IP a clean start after a typo-then-success', async () => {
        const { middleware, audits } = buildMiddleware();
        const ip = uniqueIp();
        const studentA = uniqueId('student-a');
        for (let i = 0; i < 3; i++) await send(middleware, loginRequest({ deviceId: studentA, ip, email: 'a@x.edu.ph' }));
        loginSucceeded(studentA, ip, 'a@x.edu.ph');

        const result = await send(middleware, loginRequest({ deviceId: uniqueId('student-b'), ip, email: 'b@x.edu.ph' }));

        expect(result.passed).toBe(true);
        expect(audits.at(-1).score).toBe(0);
    });
});

describe('securityMiddleware - account layer after login (#2)', () => {
    it('blocks a stolen admin session rotating x-device-id on its 3rd request, account-wide (was 200 of 200 passing)', async () => {
        const { middleware, store, audits } = buildMiddleware(undefined, { resolve: async () => ({ id: 4201, role: 'admin' }) });
        const ip = uniqueIp();
        const outcomes = [];
        await withClock(async (advance) => {
            for (let i = 0; i < 20; i++) {
                advance(50); // 20 req/s
                outcomes.push(await send(middleware, adminDelete({ deviceId: uniqueId('rotating'), ip })));
            }
        });

        expect(outcomes.slice(0, 3).map(o => o.passed)).toEqual([true, true, false]);
        expect(outcomes.slice(2).every(o => o.status === 403)).toBe(true);
        expect(store.rows.get('user:4201')?.isBlocked).toBe(true);
        expect(audits[2].reason).toMatch(/^Account admin@x\.edu\.ph triggered BLOCK on DELETE \/api\/students\/:id \(requests from every device signed in to it; device \S+ alone scored 0\)/);
    });

    it('still blocks just the device when one device tells the whole story (ties go to the device)', async () => {
        const { middleware, store } = buildMiddleware(undefined, { resolve: async () => ({ id: 4202, role: 'admin' }) });
        const deviceId = uniqueId('fixed-admin');
        await withClock(async (advance) => {
            for (let i = 0; i < 5; i++) {
                advance(50);
                await send(middleware, adminDelete({ deviceId, ip: uniqueIp() }));
            }
        });

        expect(store.rows.get(deviceId)?.isBlocked).toBe(true);
        expect(store.rows.has('user:4202')).toBe(false);
    });
});

describe('securityMiddleware - never learning an attack as normal (#3)', () => {
    it('keeps a steady 5 req/s flood throttled instead of learning it (was 599 of 600 passing)', async () => {
        const { middleware } = buildMiddleware(undefined, { resolve: async () => ({ id: 4301, role: 'admin' }) });
        const deviceId = uniqueId('steady');
        const outcomes = [];
        await withClock(async (advance) => {
            for (let i = 0; i < 150; i++) {
                advance(200);
                outcomes.push(await send(middleware, adminDelete({ deviceId, ip: '198.51.100.30' })));
            }
        });

        // Requests 1-2 have no rate yet; from the 3rd on, 5 x 3 x 1 x 5 = 75,
        // the admin THROTTLE threshold (60 + 15), every single time.
        expect(outcomes.slice(0, 2).every(o => o.passed)).toBe(true);
        expect(outcomes.slice(2).every(o => o.status === 429)).toBe(true);
    });

    it('blocks a 20 req/s flood again the moment its lockout ends (was ~1,800 passing after the first block)', async () => {
        const { middleware } = buildMiddleware(undefined, { resolve: async () => ({ id: 4302, role: 'admin' }) });
        const deviceId = uniqueId('flood');
        const outcomes = [];
        await withClock(async (advance) => {
            for (let i = 0; i < 1800; i++) { // 90 s
                advance(50);
                outcomes.push(await send(middleware, adminDelete({ deviceId, ip: '198.51.100.31' })));
            }
        });

        expect(outcomes.filter(o => o.passed)).toHaveLength(2);
    });
});

describe('securityMiddleware - endpoint weight from the matched route (#4)', () => {
    it('weights a bulk-seeded student DELETE at 3x through its route pattern (was 1x)', async () => {
        const { middleware, audits } = buildMiddleware(undefined, { resolve: async () => ({ id: 4401, role: 'admin' }) });
        await send(middleware, adminDelete({ deviceId: uniqueId('weight'), ip: uniqueIp() }));
        expect(audits[0].reason).toMatch(/\| 0 x 3 x 1 x 5 = 0$/);
    });

    it('keeps the router mount path, so /login still scores at its 2x weight', async () => {
        const { middleware, audits } = buildMiddleware();
        const deviceId = uniqueId('weight-login');
        const ip = uniqueIp();
        await send(middleware, loginRequest({ deviceId, ip, email: 'x@x.edu.ph' }));
        await send(middleware, loginRequest({ deviceId, ip, email: 'x@x.edu.ph' }));
        expect(audits[1].reason).toMatch(/ x 2 x /);
    });
});

describe('readVerdict - Security Logs badge colors (#10)', () => {
    it('reads the verdict from the fixed position the server writes it', () => {
        expect(readVerdict('Device DEV-1a2b3c4d triggered LOG | 2 x 2 x 1.5 x 5 = 30')).toBe('LOG');
        expect(readVerdict('IP 203.0.113.7 triggered BLOCK (recent login attempts from any device; device DEV-x alone scored 0) | 2 x 2 x 4.5 x 5 = 90')).toBe('BLOCK');
        expect(readVerdict('Account admin@x.edu.ph triggered THROTTLE (requests from every device signed in to it; device DEV-x alone scored 0) | 5 x 3 x 1 x 5 = 75')).toBe('THROTTLE');
        expect(readVerdict('IP 203.0.113.7 triggered BLOCK (unauthorized network origin - admin portal is Campus-Intranet-restricted) | NETWORK POLICY VIOLATION')).toBe('BLOCK');
    });

    it('cannot be steered by a device ID that spells a verdict (a BLOCK used to render green)', () => {
        expect(readVerdict('Device DEV-ALLOWED triggered BLOCK | 1000 x 2 x 2 x 5 = 100')).toBe('BLOCK');
        expect(readVerdict('Device ALLOW triggered BLOCK | 1000 x 2 x 2 x 5 = 100')).toBe('BLOCK');
        expect(readVerdict('Device BLOCK triggered ALLOW | 0 x 2 x 1 x 5 = 0')).toBe('ALLOW');
    });

    it('returns null for anything that is not a WEVA evaluation', () => {
        expect(readVerdict('User logged in successfully.')).toBeNull();
        expect(readVerdict('Invalid password attempted. triggered BLOCK')).toBeNull();
        expect(readVerdict(null)).toBeNull();
    });
});
