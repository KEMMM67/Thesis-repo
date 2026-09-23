import { describe, it, expect, vi, afterEach } from 'vitest';
import { getFeatures, updateFeatures, isAuthAttemptEndpoint } from './monitor.js';

describe('monitor', () => {
    afterEach(() => vi.useRealTimers());

    it('reports requests landing in the same millisecond as a burst, not as zero velocity', () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(Date.parse('2026-09-24T00:00:00Z'));
        const device = 'same-ms-device';

        updateFeatures(device, '/api/login');
        updateFeatures(device, '/api/login');

        // 2 prior requests inside one millisecond -> at least 2000 req/s.
        expect(getFeatures(device, '/api/login').requestRate).toBe(2000);
    });

    it('treats password and OTP endpoints as authentication attempts', () => {
        expect(isAuthAttemptEndpoint('/api/login')).toBe(true);
        expect(isAuthAttemptEndpoint('/api/verify-otp')).toBe(true);
        expect(isAuthAttemptEndpoint('/api/students/me')).toBe(false);
    });
});
