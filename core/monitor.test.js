import { describe, it, expect, vi, afterEach } from 'vitest';
import { getFeatures, updateFeatures, isAuthAttemptEndpoint, settleDeviceAttempts } from './monitor.js';

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

    it('counts attempts against every account as outstanding (password spraying counts too)', () => {
        const device = 'spraying-device';
        updateFeatures(device, '/api/login', 'a@x.edu.ph');
        updateFeatures(device, '/api/login', 'b@x.edu.ph');
        updateFeatures(device, '/api/login', 'c@x.edu.ph');
        expect(getFeatures(device, '/api/login').loginAttempts).toBe(3);
    });

    it('a successful login settles only its own account: guesses at another account stay outstanding', () => {
        const device = 'own-account-trick-device';
        updateFeatures(device, '/api/login', 'victim@x.edu.ph');
        updateFeatures(device, '/api/login', 'victim@x.edu.ph');
        updateFeatures(device, '/api/login', 'victim@x.edu.ph');
        updateFeatures(device, '/api/login', 'attacker@x.edu.ph');

        settleDeviceAttempts(device, 'attacker@x.edu.ph');

        const features = getFeatures(device, '/api/login');
        // Before this fix a success reset the device to 0 attempts.
        expect(features.loginAttempts).toBe(3);
        // Velocity restarts either way (see settleDeviceAttempts' docs).
        expect(features.requestRate).toBe(0);
    });

    it('a typo-then-success on your own account leaves a clean slate', () => {
        const device = 'typo-device';
        updateFeatures(device, '/api/login', 'me@x.edu.ph');
        updateFeatures(device, '/api/login', 'me@x.edu.ph');
        updateFeatures(device, '/api/login', 'me@x.edu.ph');

        settleDeviceAttempts(device, 'me@x.edu.ph');

        expect(getFeatures(device, '/api/login').loginAttempts).toBe(0);
    });
});
