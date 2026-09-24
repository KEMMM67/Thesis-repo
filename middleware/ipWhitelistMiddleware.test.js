import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createIpWhitelistForAdminLogin } from './ipWhitelistMiddleware.js';

/**
 * @fileoverview The Admin Portal's campus-network gate, with fake adapters.
 * It must refuse the Admin Portal from outside whatever email is typed -
 * it used to refuse only administrator emails, which told outsiders which
 * emails those were - and must never gate the Student Portal.
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
    const blocked = [];
    const gate = createIpWhitelistForAdminLogin({
        auditSink: { recordEvaluation: async (evaluation) => { intrusions.push(evaluation); } },
        ipTrackingStore: { block: async (key) => { blocked.push(key); } }
    });
    return { gate, intrusions, blocked };
}

async function attempt(gate, { ip, email, portal }) {
    const req = { ip, baseUrl: '/api', path: '/login', body: { email, ...(portal ? { portal } : {}) } };
    const res = { statusCode: null, body: null, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    let passed = false;
    await gate(req, res, () => { passed = true; });
    return { passed, res };
}

describe('createIpWhitelistForAdminLogin', () => {
    it('refuses the Admin Portal from outside the campus network, the same way for any email', async () => {
        const { gate, intrusions, blocked } = buildGate();
        for (const email of ['real-admin@x.edu.ph', 'no-such-user@x.edu.ph', 'student@x.edu.ph']) {
            const { passed, res } = await attempt(gate, { ip: '203.0.113.50', email, portal: 'admin' });
            expect(passed).toBe(false);
            expect([res.statusCode, res.body]).toEqual([403, { error: 'Network Access Denied', message: 'Admin portal can only be accessed from the Campus Intranet.' }]);
        }
        expect(intrusions).toHaveLength(3);
        expect(blocked).toEqual(['203.0.113.50', '203.0.113.50', '203.0.113.50']);
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

    it('enforces nothing while the whitelist is switched off', async () => {
        process.env.ENABLE_IP_WHITELIST = 'false';
        const { gate } = buildGate();
        expect((await attempt(gate, { ip: '203.0.113.50', email: 'real-admin@x.edu.ph', portal: 'admin' })).passed).toBe(true);
    });
});
