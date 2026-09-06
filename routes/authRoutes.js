import { Router } from "express";
import { login, verifyOtp } from "../controllers/authController.js";

/**
 * @fileoverview Authentication routes.
 *
 * Both routes run through the injected `securityMiddleware` (WEVA) before
 * their controller ever executes: a brute-force burst against either is
 * scored on request velocity/fail-rate alone and can be THROTTLEd or
 * BLOCKed here, before it reaches a single bcrypt.compare(), OTP
 * comparison, or database query (see core/scorer.js, core/mitigation.js).
 * middleware/authMiddleware.js is deliberately not applied to either -
 * neither a login request nor an OTP verification has a token yet to
 * verify.
 *
 * Both also run through the injected network-perimeter gate (see
 * middleware/ipWhitelistMiddleware.js), ahead of `securityMiddleware`, so
 * a disallowed network origin is rejected before it can even contribute
 * to WEVA's behavioral scoring. /verify-otp uses `ipWhitelistMiddleware`
 * (it is reachable only from the admin login chain - see
 * controllers/authController.js); /login uses the role-aware
 * `ipWhitelistForAdminLogin`, since that route is shared with the student
 * portal and must never gate a student's login.
 *
 * POST /login authenticates by password. For a student/faculty account
 * that's the whole login; for an admin account it instead returns
 * { requireOtp: true } and emails a one-time code, and the login is only
 * completed by POST /verify-otp confirming that code - see
 * controllers/authController.js for the full two-step design.
 *
 * This is a factory, not a bare router, because `securityMiddleware`,
 * `ipWhitelistMiddleware`, and `ipWhitelistForAdminLogin` are themselves
 * factory-built (see the createSecurityMiddleware()/
 * createIpWhitelistMiddleware()/createIpWhitelistForAdminLogin() docs)
 * from adapters that only server.js - the composition root - is meant to
 * construct. Passing the already-built middleware in here, rather than
 * this file constructing its own, guarantees every route in this app
 * shares exactly one instance of each, backed by exactly one set of
 * adapters.
 *
 * Mounted at "/api" in server.js, so these resolve to POST /api/login and
 * POST /api/verify-otp.
 *
 * @param {object} deps
 * @param {import("express").RequestHandler} deps.securityMiddleware
 * @param {import("express").RequestHandler} deps.ipWhitelistMiddleware
 * @param {import("express").RequestHandler} deps.ipWhitelistForAdminLogin
 * @returns {import("express").Router}
 */
export function createAuthRoutes({ securityMiddleware, ipWhitelistMiddleware, ipWhitelistForAdminLogin }) {
    const router = Router();

    router.post("/login", ipWhitelistForAdminLogin, securityMiddleware, login);
    router.post("/verify-otp", ipWhitelistMiddleware, securityMiddleware, verifyOtp);

    return router;
}
