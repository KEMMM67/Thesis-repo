import { describe, it, expect, vi, beforeAll } from 'vitest';
import bcrypt from 'bcryptjs';
import { login, verifyOtp } from './authController.js';
import { getFeatures, updateFeatures } from '../core/monitor.js';
import { countRecentAttempts, recordAttempt } from '../core/ipAttempts.js';

/**
 * @fileoverview The login controller against an in-memory stand-in for the
 * database (no Postgres, no email). Covers the two authentication fixes:
 * a successful login settles only its own account's WEVA attempts, and an
 * OTP allows 5 wrong guesses and exactly one use.
 */

const db = vi.hoisted(() => ({ users: new Map() }));

vi.mock('../config/prisma.js', () => {
    // Every read yields once before answering, like a real database round
    // trip - which is what lets simultaneous requests interleave in these tests.
    const tick = () => new Promise(resolve => setImmediate(resolve));
    const byEmail = (email) => [...db.users.values()].find(u => u.email === email);
    return {
        default: {
            user: {
                async findUnique({ where }) { await tick(); const u = byEmail(where.email); return u ? { ...u } : null; },
                async update({ where, data }) { await tick(); Object.assign(db.users.get(where.id), data); return { ...db.users.get(where.id) }; },
                async updateMany({ where, data }) {
                    await tick();
                    const u = db.users.get(where.id);
                    if (!u || u.otpCode !== where.otpCode) return { count: 0 };
                    Object.assign(u, data);
                    return { count: 1 };
                }
            },
            session: { async upsert() { return {}; } },
            loginAttempt: { async create() { return {}; } },
            behaviorLog: { async create() { return {}; } }
        }
    };
});

vi.mock('../utils/emailService.js', () => ({
    sendLoginAlert: vi.fn(async () => {}),
    sendOtpEmail: vi.fn(async () => true)
}));

beforeAll(() => {
    process.env.JWT_SECRET ??= 'test-only-secret';
});

const hash = (password) => bcrypt.hashSync(password, 4);

function fakeRes() {
    return {
        statusCode: 200,
        body: null,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; }
    };
}

async function call(handler, req) {
    const res = fakeRes();
    await handler(req, res);
    return res;
}

function addAdmin(id, overrides = {}) {
    const user = {
        id, email: `admin${id}@x.edu.ph`, role: 'admin', passwordHash: hash('right-password'),
        otpCode: '654321', otpExpiresAt: new Date(Date.now() + 60_000), ...overrides
    };
    db.users.set(id, user);
    return user;
}

const otpRequest = (user, otp) => ({ body: { email: user.email, otp }, headers: { 'x-device-id': `DEV-otp-${user.id}` }, ip: '203.0.113.91' });

describe('login - settling WEVA attempts (#1)', () => {
    it('settles only the attempts aimed at the account that logged in, on the device and the IP', async () => {
        const deviceId = 'DEV-ctrl-own-account';
        const ip = '203.0.113.90';
        db.users.set(100, { id: 100, email: 'attacker@x.edu.ph', role: 'student', passwordHash: hash('right-password') });
        for (let i = 0; i < 3; i++) {
            updateFeatures(deviceId, '/api/login', 'victim@x.edu.ph');
            recordAttempt(ip, 'victim@x.edu.ph');
        }
        updateFeatures(deviceId, '/api/login', 'attacker@x.edu.ph');
        recordAttempt(ip, 'attacker@x.edu.ph');

        const res = await call(login, { body: { email: 'attacker@x.edu.ph', password: 'right-password' }, headers: { 'x-device-id': deviceId }, ip });

        expect(res.body.token).toBeTruthy();
        // The attacker's own attempt is settled; the 3 guesses at the victim are not.
        expect(getFeatures(deviceId, '/api/login').loginAttempts).toBe(3);
        expect(countRecentAttempts(ip)).toBe(3);
    });
});

describe('verifyOtp - attempt cap and single use (#5)', () => {
    it('cancels a code after 5 wrong guesses, after which even the right code is refused', async () => {
        const admin = addAdmin(1);
        const messages = [];
        for (let i = 0; i < 5; i++) messages.push((await call(verifyOtp, otpRequest(admin, '000000'))).body.message);

        expect(messages.slice(0, 4)).toEqual([
            'Invalid OTP. 4 attempts left before this code is cancelled.',
            'Invalid OTP. 3 attempts left before this code is cancelled.',
            'Invalid OTP. 2 attempts left before this code is cancelled.',
            'Invalid OTP. 1 attempt left before this code is cancelled.'
        ]);
        expect(messages[4]).toMatch(/cancelled/);
        expect(db.users.get(1).otpCode).toBeNull();

        const late = await call(verifyOtp, otpRequest(admin, '654321'));
        expect(late.statusCode).toBe(401);
        expect(late.body.token).toBeUndefined();
    });

    it('counts simultaneous guesses one after another: 20 in parallel get 5 comparisons, and a right one among the rest is refused', async () => {
        const admin = addAdmin(2);
        const guesses = Array.from({ length: 20 }, (_, i) => (i === 9 ? '654321' : String(i).padStart(6, '0')));

        const results = await Promise.all(guesses.map(guess => call(verifyOtp, otpRequest(admin, guess))));

        expect(results.some(r => r.body.token)).toBe(false);
        expect(results.filter(r => /attempts? left/.test(r.body.message))).toHaveLength(4);
        expect(results.slice(4).every(r => r.statusCode === 401 && /cancelled/.test(r.body.message))).toBe(true);
    });

    it('lets a code be used exactly once, even by two simultaneous requests', async () => {
        const admin = addAdmin(3);
        const [first, second] = await Promise.all([
            call(verifyOtp, otpRequest(admin, '654321')),
            call(verifyOtp, otpRequest(admin, '654321'))
        ]);

        expect([first, second].filter(r => r.body.token)).toHaveLength(1);
        expect([first, second].find(r => !r.body.token).statusCode).toBe(401);
    });

    it('gives a freshly issued code its own 5 guesses', async () => {
        const admin = addAdmin(4);
        for (let i = 0; i < 3; i++) await call(verifyOtp, otpRequest(admin, '000000'));

        // Signing in again issues a new code (controllers/authController.js#beginOtpChallenge).
        const relogin = await call(login, { body: { email: admin.email, password: 'right-password' }, headers: { 'x-device-id': 'DEV-otp-4' }, ip: '203.0.113.91' });
        expect(relogin.body.requireOtp).toBe(true);

        const wrong = db.users.get(4).otpCode === '000000' ? '111111' : '000000';
        const messages = [];
        for (let i = 0; i < 4; i++) messages.push((await call(verifyOtp, otpRequest(admin, wrong))).body.message);
        expect(messages.at(-1)).toBe('Invalid OTP. 1 attempt left before this code is cancelled.');
    });
});
