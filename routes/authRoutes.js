import { Router } from "express";
import { login, verifyOtp } from "../controllers/authController.js";
import { securityMiddleware } from "../middleware/securityMiddleware.js";

/**
 * @fileoverview Authentication routes.
 *
 * Both routes run through securityMiddleware (WEVA) before their
 * controller ever executes: a brute-force burst against either is scored
 * on request velocity/fail-rate alone and can be THROTTLEd or BLOCKed
 * here, before it reaches a single bcrypt.compare(), OTP comparison, or
 * database query (see core/scorer.js, core/mitigation.js). authMiddleware
 * is deliberately not applied to either - neither a login request nor an
 * OTP verification has a token yet to verify.
 *
 * POST /login authenticates by password. For a student/faculty account
 * that's the whole login; for an admin account it instead returns
 * { requireOtp: true } and emails a one-time code, and the login is only
 * completed by POST /verify-otp confirming that code - see
 * controllers/authController.js for the full two-step design.
 *
 * Mounted at "/api" in server.js, so these resolve to POST /api/login and
 * POST /api/verify-otp.
 */
const router = Router();

router.post("/login", securityMiddleware, login);
router.post("/verify-otp", securityMiddleware, verifyOtp);

export default router;
