import { describe, it, expect } from 'vitest';
import { createWeva } from './weva.js';

/**
 * @fileoverview Proves createWeva() - the framework's single public entry
 * point - actually validates its required adapters and returns a fully
 * wired, Express-shaped middleware surface. Uses bare fake adapters (no
 * Prisma, no database) since these tests only need to prove the factory's
 * own contract, not the Prisma adapters' behavior (already covered by
 * core/mitigation.test.js and, indirectly, the app's own request path).
 */

const fakeAuditSink = () => ({ recordEvaluation: async () => {} });
const fakeIpTrackingStore = () => ({ findStatus: async () => null, block: async () => {}, clear: async () => {} });
const fakeIdentityResolver = () => ({ resolve: async () => null });

function fullFakeConfig() {
    return {
        auditSink: fakeAuditSink(),
        ipTrackingStore: fakeIpTrackingStore(),
        identityResolver: fakeIdentityResolver()
    };
}

describe('createWeva', () => {
    it('throws a clear, named error when a required adapter is missing', () => {
        const { auditSink, ipTrackingStore } = fullFakeConfig(); // identityResolver omitted
        expect(() => createWeva({ auditSink, ipTrackingStore })).toThrow(/identityResolver/);
    });

    it('throws when called with no config at all, rather than crashing on the first request', () => {
        expect(() => createWeva()).toThrow(/auditSink/);
    });

    it('returns the full middleware surface as Express-shaped request handlers', () => {
        const weva = createWeva(fullFakeConfig());

        for (const name of ['securityMiddleware', 'ipWhitelistMiddleware', 'ipWhitelistForAdminLogin', 'authRoutes']) {
            expect(typeof weva[name]).toBe('function');
        }

        const middleware = weva.securityMiddleware();
        expect(typeof middleware).toBe('function');
        expect(middleware.length).toBe(3); // (req, res, next)
    });

    it('returns the same cached middleware instance on repeated calls', () => {
        const weva = createWeva(fullFakeConfig());
        expect(weva.securityMiddleware()).toBe(weva.securityMiddleware());
        expect(weva.ipWhitelistMiddleware()).toBe(weva.ipWhitelistMiddleware());
    });
});
