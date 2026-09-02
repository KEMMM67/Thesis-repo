import { Router } from "express";
import { login } from "../controllers/authController.js";
import { securityMiddleware } from "../middleware/securityMiddleware.js";

/**
 * @fileoverview Authentication routes.
 *
 * POST /login runs through securityMiddleware (WEVA) before
 * authController.login ever executes: a brute-force burst against this
 * route is scored on request velocity alone and can be THROTTLEd or
 * BLOCKed here, before it reaches a single bcrypt.compare() call or
 * database query (see core/scorer.js, core/mitigation.js). authMiddleware
 * is deliberately not applied - a login request has no token yet to
 * verify.
 *
 * Mounted at "/api" in server.js, so this route resolves to POST /api/login.
 */
const router = Router();

router.post("/login", securityMiddleware, login);

export default router;
