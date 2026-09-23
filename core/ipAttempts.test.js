import { describe, it, expect, vi, afterEach } from 'vitest';
import { countRecentAttempts, recordAttempt, clearAttempts } from './ipAttempts.js';
import { securityConfig } from '../config/securityConfig.js';

describe('ipAttempts', () => {
    afterEach(() => vi.useRealTimers());

    it('counts attempts inside the window and forgets them once they age out', () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        const ip = '192.0.2.10';
        const start = Date.parse('2026-09-24T00:00:00Z');

        vi.setSystemTime(start);
        recordAttempt(ip);
        recordAttempt(ip);
        expect(countRecentAttempts(ip)).toBe(2);

        vi.setSystemTime(start + securityConfig.windowMs - 1);
        expect(countRecentAttempts(ip)).toBe(2);

        vi.setSystemTime(start + securityConfig.windowMs);
        expect(countRecentAttempts(ip)).toBe(0);
    });

    it('clearAttempts() resets the count (a successful login from that IP)', () => {
        const ip = '192.0.2.11';
        recordAttempt(ip);
        recordAttempt(ip);
        clearAttempts(ip);
        expect(countRecentAttempts(ip)).toBe(0);
    });

    it('keeps each IP separate', () => {
        recordAttempt('192.0.2.12');
        expect(countRecentAttempts('192.0.2.13')).toBe(0);
    });
});
