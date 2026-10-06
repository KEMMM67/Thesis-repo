import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createIpWhitelistForAdminLogin } from './ipWhitelistMiddleware.js';
import { createSecurityMiddleware } from './securityMiddleware.js';

/**
 * @fileoverview The Admin Portal's campus-network gate, with fake adapters.
 * It must refuse the Admin Portal from outside whatever email is typed -
 * it used to refuse only administrator emails, which told outsiders which
 * emails those were - and must never gate the Student Portal, either
 * directly or by blocking an address that students share.
 */

const saved = {};

beforeEach(() => {
    for (const key of ['ENABLE_IP_WHITELIST', 'ALLOWED_ADMIN_IPS']) saved[key] = process.env[key];
    process.env.ENABLE_IP_WHITELIST = 'true';
    process.env.ALLOWED_ADMIN_IPS = '10.0.0.5';
});

afterEach(() => {
    for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
});

function buildGate() {
    const intrusions = [];
    const gate = createIpWhitelistForAdminLogin({
        auditSink: { recordEvaluation: async (evaluation) => { intrusions.push(evaluation); } }
    });
    return { gate, intrusions };
}

function fakeResponse() {
    return { statusCode: null, body: null, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}

async function attempt(gate, { ip, email, portal }) {
    const req = { ip, baseUrl: '/api', path: '/login', body: { email, ...(portal ? { portal } : {}) } };
    const res = fakeResponse();
    let passed = false;
    await gate(req, res, () => { passed = true; });
    return { passed, res };
}

/** Runs `req` through `middlewares` in order, as Express would, stopping at the first that does not call next(). */
async function throughChain(middlewares, req) {
    const res = fakeResponse();
    for (const middleware of middlewares) {
        let passed = false;
        await middleware(req, res, () => { passed = true; });
        if (!passed) return { passed: false, res };
    }
    return { passed: true, res };
}

describe('createIpWhitelistForAdminLogin', () => {
    it('refuses the Admin Portal from outside the campus network, the same way for any email', async () => {
        const { gate, intrusions } = buildGate();
        for (const email of ['real-admin@x.edu.ph', 'no-such-user@x.edu.ph', 'student@x.edu.ph']) {
            const { passed, res } = await attempt(gate, { ip: '203.0.113.50', email, portal: 'admin' });
            expect(passed).toBe(false);
            expect([res.statusCode, res.body]).toEqual([403, { error: 'Network Access Denied', message: 'Admin portal can only be accessed from the Campus Intranet.' }]);
        }
        expect(intrusions).toHaveLength(3);
        expect(intrusions.every(entry => entry.actionTaken === 'BLOCK' && entry.riskLevel === 'CRITICAL')).toBe(true);
    });

    it('blocks no address, so students sharing an outsider\'s IP can still sign in (it used to block it for 60 s)', async () => {
        // WEVA's own block store, the one core/mitigation.js enforces. The
        // gate is handed it too, as core/weva.js used to, so a gate that
        // wrote to it again would fail here.
        const rows = new Map();
        const store = {
            async findStatus(id) { return rows.get(id) ?? null; },
            async block(id, blockedUntil) { rows.set(id, { isBlocked: true, blockedUntil }); },
            async clear(id) { rows.delete(id); }
        };
        const auditSink = { recordEvaluation: async () => {} };
        const gate = createIpWhitelistForAdminLogin({ auditSink, ipTrackingStore: store });
        const weva = createSecurityMiddleware({ auditSink, ipTrackingStore: store, identityResolver: { resolve: async () => null } });

        // One person behind a shared address (a boarding house, mobile data) tries the Admin Portal...
        const sharedIp = '203.0.113.77';
        expect((await attempt(gate, { ip: sharedIp, email: 'curious@x.edu.ph', portal: 'admin' })).passed).toBe(false);

        // ...and a student behind the same address signs in to the Student Portal, through
        // the same chain as routes/authRoutes.js: this gate, then WEVA.
        const student = {
            headers: { 'x-device-id': 'DEV-neighbour' }, ip: sharedIp, method: 'POST',
            baseUrl: '/api', path: '/login', route: { path: '/login' }, body: { email: 'student@x.edu.ph' }
        };
        const { passed, res } = await throughChain([gate, weva], student);
        expect([passed, res.statusCode]).toEqual([true, null]);
        expect(rows.size).toBe(0);
    });

    it('never gates the Student Portal - not even for an administrator email - so it reveals nothing either', async () => {
        const { gate, intrusions } = buildGate();
        expect((await attempt(gate, { ip: '203.0.113.50', email: 'real-admin@x.edu.ph' })).passed).toBe(true);
        expect(intrusions).toHaveLength(0);
    });

    it('lets the Admin Portal through from a whitelisted address, including its IPv4-mapped form', async () => {
        const { gate } = buildGate();
        expect((await attempt(gate, { ip: '10.0.0.5', email: 'real-admin@x.edu.ph', portal: 'admin' })).passed).toBe(true);
        expect((await attempt(gate, { ip: '::ffff:10.0.0.5', email: 'real-admin@x.edu.ph', portal: 'admin' })).passed).toBe(true);
    });

    it('lets the Admin Portal through from anywhere in a whitelisted range, and refuses the next one over', async () => {
        process.env.ALLOWED_ADMIN_IPS = '127.0.0.1, 203.0.113.0/24';
        const { gate, intrusions } = buildGate();
        for (const ip of ['203.0.113.17', '203.0.113.42', '::ffff:203.0.113.99']) {
            expect((await attempt(gate, { ip, email: 'real-admin@x.edu.ph', portal: 'admin' })).passed).toBe(true);
        }
        expect((await attempt(gate, { ip: '203.0.114.1', email: 'real-admin@x.edu.ph', portal: 'admin' })).passed).toBe(false);
        expect(intrusions).toHaveLength(1);
    });

    it('refuses everyone when the only entry is a range too broad to accept', async () => {
        process.env.ALLOWED_ADMIN_IPS = '0.0.0.0/0';
        const { gate } = buildGate();
        expect((await attempt(gate, { ip: '203.0.113.50', email: 'real-admin@x.edu.ph', portal: 'admin' })).passed).toBe(false);
    });

    it('enforces nothing while the whitelist is switched off', async () => {
        process.env.ENABLE_IP_WHITELIST = 'false';
        const { gate } = buildGate();
        expect((await attempt(gate, { ip: '203.0.113.50', email: 'real-admin@x.edu.ph', portal: 'admin' })).passed).toBe(true);
    });
});
