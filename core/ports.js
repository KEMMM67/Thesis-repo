/**
 * @fileoverview Port definitions for WEVA's Hexagonal Architecture.
 *
 * A "port" here is a contract the security pipeline (core/mitigation.js,
 * middleware/securityMiddleware.js, middleware/ipWhitelistMiddleware.js)
 * depends on, without knowing or caring which concrete storage technology
 * implements it. This file has no runtime logic - JS has no interface
 * keyword, so these are documented as JSDoc typedefs, which every port
 * consumer and adapter implementation below references by import path
 * (`import("./ports.js").AuditSink`, etc.) for editor/type-checking
 * support without adopting TypeScript project-wide.
 *
 * Today's only implementations are the Prisma-backed adapters in
 * adapters/prisma/ (wired up in server.js). A host application on a
 * different database, or a test that wants zero real I/O, implements the
 * same three methods against whatever storage it likes - nothing in
 * core/ or middleware/ needs to change either way.
 *
 * @typedef {object} WevaEvaluation
 * Everything needed to record one WEVA verdict as an auditable event.
 * `reason` is used for both the human-readable SecurityAction narrative
 * and the BehaviorLog description - in every call site in this app they
 * are always the same string, describing the same event from two angles
 * that happen to coincide.
 * @property {string} userEmail - "unauthenticated" for pre-auth events.
 * @property {number|null} userId - Resolved via IdentityResolver; null if unresolved or unauthenticated.
 * @property {number} score - 0-100 anomaly score (core/scorer.js).
 * @property {"LOW"|"MEDIUM"|"HIGH"|"CRITICAL"} riskLevel
 * @property {"ALLOW"|"LOG"|"THROTTLE"|"BLOCK"} actionTaken - Verdict from core/decisionEngine.js.
 * @property {string} reason - Human-readable narrative (see above).
 * @property {string} eventType - e.g. "SECURITY_EVALUATION", "NETWORK_ACCESS_DENIED".
 *
 * @typedef {object} AuditSink
 * Persists one WEVA verdict as an auditable record. Implementations should
 * never let a persistence failure propagate to the caller - a database
 * hiccup must not be allowed to break the security decision it is merely
 * trying to log; catch and log internally instead (see
 * adapters/prisma/auditSink.js).
 * @property {(evaluation: WevaEvaluation) => Promise<void>} recordEvaluation
 *
 * @typedef {object} IpBlockStatus
 * @property {boolean} isBlocked
 * @property {Date|null} blockedUntil
 *
 * @typedef {object} IpTrackingStore
 * Tracks which device/IP identifiers are under an active temporary block.
 * `identifier` is typically the `x-device-id` header, falling back to the
 * request IP (see core/monitor.js) - not necessarily a literal IP address,
 * despite the name.
 * @property {(identifier: string) => Promise<IpBlockStatus|null>} findStatus - Null if the identifier has never been tracked.
 * @property {(identifier: string, blockedUntil: Date) => Promise<void>} block - Marks the identifier blocked until the given time.
 * @property {(identifier: string) => Promise<void>} clear - Lifts a stale/expired block. Best-effort: a failure here should not affect the current request.
 *
 * @typedef {object} ResolvedIdentity
 * @property {number} id
 * @property {string} role
 *
 * @typedef {object} IdentityResolver
 * Looks up a user's stable id and role by email - the two pieces of
 * identity the security pipeline needs but should not have to run its own
 * user-table query for.
 * @property {(email: string) => Promise<ResolvedIdentity|null>} resolve - Null if no account matches.
 */

export {};
