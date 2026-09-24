import { createSecurityMiddleware } from "../middleware/securityMiddleware.js";
import { createIpWhitelistMiddleware, createIpWhitelistForAdminLogin } from "../middleware/ipWhitelistMiddleware.js";
import { createAuthRoutes } from "../routes/authRoutes.js";

/**
 * @fileoverview createWeva() - the single public entry point for the WEVA
 * security framework, tying together every seam built across this
 * modularization effort: Ports & Adapters (core/ports.js, adapters/prisma/)
 * for storage, and injectable tuning (core/scorer.js#defaultWevaConfig,
 * core/decisionEngine.js#defaultDecisionConfig) for scoring. A host
 * application's only interaction with WEVA's internals should be through
 * this factory - everything it returns is already fully wired.
 *
 * Usage mirrors any other Express security middleware (helmet(), cors(),
 * rateLimit()):
 *
 *   const weva = createWeva({
 *     auditSink: new PrismaAuditSink(prisma),
 *     ipTrackingStore: new PrismaIpTrackingStore(prisma),
 *     identityResolver: new PrismaIdentityResolver(prisma)
 *   });
 *
 *   app.use('/api', weva.authRoutes());
 *   app.use('/api/admin', weva.ipWhitelistMiddleware(), authMiddleware, ...);
 *   app.use(weva.securityMiddleware());
 *
 * A host on a different database supplies its own three adapters
 * (implementing core/ports.js's AuditSink/IpTrackingStore/IdentityResolver
 * contracts) instead of the Prisma-backed ones - nothing else here, or in
 * middleware/securityMiddleware.js, middleware/ipWhitelistMiddleware.js,
 * or core/mitigation.js underneath it, changes.
 *
 * The lower-level factories this wraps (createSecurityMiddleware(),
 * createIpWhitelistMiddleware(), createIpWhitelistForAdminLogin(),
 * createAuthRoutes()) stay exported from their own files too - createWeva()
 * is a convenience for the common case, not the only way in, for a host
 * that wants WEVA's scoring wired into its own routing instead of this
 * app's auth routes.
 */

/**
 * @param {object} config
 * @param {import("./ports.js").AuditSink} config.auditSink - Required. Persists WEVA verdicts.
 * @param {import("./ports.js").IpTrackingStore} config.ipTrackingStore - Required. Tracks active blocks.
 * @param {import("./ports.js").IdentityResolver} config.identityResolver - Required. Resolves a user's id/role by email.
 * @param {object} [config.wevaConfig] - Overrides for core/scorer.js#computeScore (endpointWeights, minVelocityFloor, failRateIncrement, velocityPointScale, defaultEndpointWeight). Defaults to defaultWevaConfig - this app's exact current tuning - when omitted.
 * @param {object} [config.decisionConfig] - Overrides for core/decisionEngine.js#decideAction (thresholds, roleTolerance). Defaults to defaultDecisionConfig when omitted.
 * @returns {{
 *   securityMiddleware: () => import("express").RequestHandler,
 *   ipWhitelistMiddleware: () => import("express").RequestHandler,
 *   ipWhitelistForAdminLogin: () => import("express").RequestHandler,
 *   authRoutes: () => import("express").Router
 * }} Every accessor returns the same cached instance on every call - one
 *    security pipeline per `createWeva()` call, not a fresh one per access.
 * @throws {Error} If `auditSink`, `ipTrackingStore`, or `identityResolver`
 *         is missing - fails loudly at startup rather than mysteriously on
 *         the first request.
 */
export function createWeva(config) {
    const { auditSink, ipTrackingStore, identityResolver } = config || {};

    for (const [name, dep] of Object.entries({ auditSink, ipTrackingStore, identityResolver })) {
        if (!dep) {
            throw new Error(`createWeva(): missing required adapter "${name}". See core/ports.js for the interface it must implement.`);
        }
    }

    const security = createSecurityMiddleware(config);
    const whitelist = createIpWhitelistMiddleware({ auditSink, ipTrackingStore });
    const whitelistForAdminLogin = createIpWhitelistForAdminLogin({ auditSink, ipTrackingStore });
    const routes = createAuthRoutes({
        securityMiddleware: security,
        ipWhitelistMiddleware: whitelist,
        ipWhitelistForAdminLogin: whitelistForAdminLogin
    });

    return {
        securityMiddleware: () => security,
        ipWhitelistMiddleware: () => whitelist,
        ipWhitelistForAdminLogin: () => whitelistForAdminLogin,
        authRoutes: () => routes
    };
}
