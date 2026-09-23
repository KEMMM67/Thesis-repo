import { describe, it, expect } from 'vitest';
import { computeScore } from './scorer.js';

/**
 * @fileoverview Locks in the worked examples documented directly in
 * computeScore()'s own docblock (see scorer.js), so nothing before or
 * after this file's Step 3 refactor - moving endpointWeights,
 * minVelocityFloor, failRateIncrement, and velocityPointScale out of
 * hardcoded module constants and into a caller-supplied `config` object -
 * can silently change what the algorithm actually outputs for these five
 * scenarios.
 */
describe('WEVA computeScore', () => {
    it('scores idle browsing (no velocity deviation) as 0 -> ALLOW', () => {
        const { score } = computeScore(
            { requestRate: 0, loginAttempts: 0, endpoint: '/api/students/view' },
            { requestRate: 0 }
        );
        expect(score).toBe(0);
    });

    it('scores a +3 req/s burst on a normal (1x) endpoint as 15', () => {
        const { score } = computeScore(
            { requestRate: 3, loginAttempts: 0, endpoint: '/api/students/view' },
            { requestRate: 0 }
        );
        expect(score).toBe(15);
    });

    it('scores the identical +3 req/s burst against a 3x mutation endpoint as 45', () => {
        const { score } = computeScore(
            // "/api/students/123" exercises normalizePath()'s collapsing of
            // a numeric ID to ":id", the same normalization PUT/DELETE
            // /api/students/:id relies on in production.
            { requestRate: 3, loginAttempts: 0, endpoint: '/api/students/123' },
            { requestRate: 0 }
        );
        expect(score).toBe(45);
    });

    it('THROTTLEs a device on its 5th unresolved login attempt at score 60', () => {
        const result = computeScore(
            // requestRate: 0 isolates minVelocityFloor's effect - this
            // score comes entirely from the floor plus the fail-rate
            // factor, not from an elevated request rate.
            { requestRate: 0, loginAttempts: 4, endpoint: '/api/login' },
            { requestRate: 0 }
        );
        expect(result.score).toBe(60);
        // Also locks in the itemized breakdown scorer.js persists for the
        // audit trail (securityMiddleware.js) and the admin dashboard's
        // Security Logs table - not just the final number.
        expect(result.breakdown).toEqual({
            velocityIncrement: 2,
            endpointWeight: 2,
            failRateFactor: 3,
            scale: 5,
            formula: '2 x 2 x 3 x 5 = 60'
        });
    });

    it('keeps the 7th attempt below block (80) and first crosses block=85 on the 8th (90)', () => {
        const seventh = computeScore({ requestRate: 0, loginAttempts: 6, endpoint: '/api/login' }, { requestRate: 0 });
        const eighth = computeScore({ requestRate: 0, loginAttempts: 7, endpoint: '/api/login' }, { requestRate: 0 });
        expect(seventh.score).toBe(80);
        expect(eighth.score).toBe(90);
    });

    it('BLOCKs the same device on its 9th unresolved login attempt at score 100', () => {
        const { score } = computeScore(
            { requestRate: 0, loginAttempts: 8, endpoint: '/api/login' },
            { requestRate: 0 }
        );
        expect(score).toBe(100);
    });

    it('respects a fully custom config, proving the injection is actually wired through', () => {
        // Deliberately unlike defaultWevaConfig in every field, so this
        // could only pass if computeScore() is truly reading from `config`
        // rather than falling back to its own hardcoded defaults.
        const customConfig = {
            minVelocityFloor: 10,
            failRateIncrement: 1,
            velocityPointScale: 1,
            defaultEndpointWeight: 1,
            endpointWeights: { '/custom/endpoint': 7 }
        };

        const { score, breakdown } = computeScore(
            { requestRate: 0, loginAttempts: 1, endpoint: '/custom/endpoint' },
            { requestRate: 0 },
            customConfig
        );

        // velocityIncrement floored to 10, endpointWeight 7, failRateFactor
        // 1 + 1*1 = 2, scale 1 -> 10 * 7 * 2 * 1 = 140, clamped to 100.
        expect(score).toBe(100);
        expect(breakdown.formula).toBe('10 x 7 x 2 x 1 = 100');
    });
});
