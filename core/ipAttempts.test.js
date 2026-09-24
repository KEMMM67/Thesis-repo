import { describe, it, expect, vi, afterEach } from 'vitest';
import { countRecentAttempts, recordAttempt, settleIpAttempts } from './ipAttempts.js';
import { securityConfig } from '../config/securityConfig.js';

describe('ipAttempts', () => {
    afterEach(() => vi.useRealTimers());

    it('counts attempts inside the window and forgets them once they age out', () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        const ip = '192.0.2.10';
        const start = Date.parse('2026-09-24T00:00:00Z');

        vi.setSystemTime(start);
        recordAttempt(ip, 'a@x.edu.ph');
        recordAttempt(ip, 'b@x.edu.ph');
        expect(countRecentAttempts(ip)).toBe(2);

        vi.setSystemTime(start + securityConfig.windowMs - 1);
        expect(countRecentAttempts(ip)).toBe(2);

        vi.setSystemTime(start + securityConfig.windowMs);
        expect(countRecentAttempts(ip)).toBe(0);
    });

    it('a successful login settles only the attempts aimed at that account', () => {
        const ip = '192.0.2.11';
        recordAttempt(ip, 'victim@x.edu.ph');
        recordAttempt(ip, 'victim@x.edu.ph');
        recordAttempt(ip, 'victim@x.edu.ph');
        recordAttempt(ip, 'attacker@x.edu.ph');

        // The attacker logs into their own account between guesses.
        settleIpAttempts(ip, 'attacker@x.edu.ph');

        // Before this fix the whole window was cleared; the guesses at the
        // victim now stay counted.
        expect(countRecentAttempts(ip)).toBe(3);
    });

    it('a typo-then-success settles itself, so the next user on a shared IP starts at 0', () => {
        const ip = '192.0.2.12';
        recordAttempt(ip, 'student-a@x.edu.ph');
        recordAttempt(ip, 'student-a@x.edu.ph');
        recordAttempt(ip, 'student-a@x.edu.ph');
        settleIpAttempts(ip, 'student-a@x.edu.ph');
        expect(countRecentAttempts(ip)).toBe(0);
    });

    it('keeps each IP separate', () => {
        recordAttempt('192.0.2.13', 'a@x.edu.ph');
        expect(countRecentAttempts('192.0.2.14')).toBe(0);
    });
});
