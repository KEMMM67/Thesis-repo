import { describe, it, expect } from 'vitest';
import { decideAction, defaultDecisionConfig } from './decisionEngine.js';
import { securityConfig } from '../config/securityConfig.js';

/**
 * @fileoverview decideAction() had no dedicated tests before this file -
 * it inherited coverage only indirectly, by being exercised through
 * middleware/securityMiddleware.js. Now that it accepts an injected
 * config (the Step 3 refactor - see decisionEngine.js), these tests pin
 * its threshold/role logic using an explicit, self-contained config
 * object rather than hardcoding numbers that merely happen to match
 * config/securityConfig.js's current .env values - so these tests stay
 * correct regardless of how this app's thresholds are tuned, and they
 * double as proof the config injection itself is wired through correctly.
 */

const testConfig = {
    thresholds: { suspicious: 25, critical: 60, block: 85 },
    roleTolerance: (role) => (role === 'admin' ? 15 : 0)
};

describe('decideAction', () => {
    it('ALLOWs a score below the suspicious threshold', () => {
        expect(decideAction(10, 'student', testConfig)).toBe('ALLOW');
    });

    it('LOGs a score at/above suspicious but below critical', () => {
        expect(decideAction(25, 'student', testConfig)).toBe('LOG');
        expect(decideAction(59, 'student', testConfig)).toBe('LOG');
    });

    it('THROTTLEs a non-admin score at/above critical but below block', () => {
        expect(decideAction(60, 'student', testConfig)).toBe('THROTTLE');
        expect(decideAction(84, 'student', testConfig)).toBe('THROTTLE');
    });

    it('BLOCKs a non-admin score at/above the block threshold', () => {
        expect(decideAction(85, 'student', testConfig)).toBe('BLOCK');
    });

    it('applies the admin role tolerance on top of the same base thresholds', () => {
        // A score of 85 BLOCKs a student (test above) but only THROTTLEs an
        // admin, since testConfig's roleTolerance raises both the block and
        // throttle thresholds by 15 for that role: 85 < 85+15=100, but
        // 85 >= 60+15=75.
        expect(decideAction(85, 'admin', testConfig)).toBe('THROTTLE');
        expect(decideAction(100, 'admin', testConfig)).toBe('BLOCK');
    });

    it('respects a fully custom config, proving the injection is actually wired through', () => {
        const strictConfig = {
            thresholds: { suspicious: 5, critical: 10, block: 15 },
            roleTolerance: () => 0
        };
        expect(decideAction(15, 'admin', strictConfig)).toBe('BLOCK');
    });

    it('falls back to defaultDecisionConfig - sourced from config/securityConfig.js - when no config is given', () => {
        // Mirrors every real call site in this app (see
        // middleware/securityMiddleware.js, which calls
        // decideAction(score, role) with no third argument). Verified
        // against securityConfig.thresholds directly, not hardcoded
        // numbers, so this test stays correct no matter how this app's
        // .env tunes the thresholds.
        expect(defaultDecisionConfig.thresholds).toBe(securityConfig.thresholds);

        const { block, critical } = securityConfig.thresholds;
        expect(decideAction(block, 'student')).toBe('BLOCK');
        expect(decideAction(critical, 'student')).toBe('THROTTLE');
    });
});
