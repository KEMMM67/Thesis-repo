import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import prisma from "../config/prisma.js";
import { resetFeatures } from "../core/monitor.js";
import { sendLoginAlert } from "../utils/emailService.js";

/**
 * @route POST /api/login
 * @access Public
 * @description Authenticates a user by email and password, issues a JWT on
 * success, persists an auditable record of the attempt, and dispatches a
 * best-effort login-alert email to the account owner (utils/emailService.js).
 *
 * Mounted behind securityMiddleware in routes/authRoutes.js: a brute-force
 * burst is scored and can be BLOCKed/THROTTLEd by WEVA before a single
 * request reaches the bcrypt.compare() or database calls below (see
 * core/scorer.js, core/mitigation.js).
 *
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @returns {Promise<void>}
 */
export async function login(req, res) {
    const { email, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress || '127.0.0.1';
    const deviceId = req.headers["x-device-id"] || req.ip;

    try {
        const user = await prisma.user.findUnique({ where: { email } });
        const passwordMatches = user ? await bcrypt.compare(password, user.passwordHash) : false;

        if (passwordMatches) {
            resetFeatures(deviceId);

            const tokenTtlMs = 60 * 60 * 1000; // must match the JWT expiresIn below
            const token = jwt.sign(
                { email: user.email, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            // Persists the Session row middleware/authMiddleware.js validates on
            // every authenticated request; without it, a token would remain
            // valid until its natural expiry with no way to revoke it early
            // (see "Force Logout" on the admin dashboard). upsert guards
            // against the vanishingly unlikely case of an identical JWT
            // (same payload, same issued-at second) without ever failing a
            // login because of it.
            try {
                await prisma.session.upsert({
                    where: { sessionToken: token },
                    update: { userId: user.id, expiresAt: new Date(Date.now() + tokenTtlMs) },
                    create: { userId: user.id, sessionToken: token, expiresAt: new Date(Date.now() + tokenTtlMs) }
                });
            } catch (sessionErr) {
                console.error("Session creation failed on login:", sessionErr.message);
                return res.status(500).json({ success: false, message: "Could not establish a secure session. Please try again." });
            }

            try {
                await Promise.all([
                    prisma.loginAttempt.create({
                        data: { userEmail: email, userId: user.id, ipAddress, status: 'SUCCESS' }
                    }),
                    prisma.behaviorLog.create({
                        data: { userEmail: email, userId: user.id, eventType: 'LOGIN_SUCCESS', description: 'User logged in successfully.' }
                    })
                ]);
            } catch (logErr) {
                console.error("Audit log write failed on successful login:", logErr.message);
            }

            // Not awaited: sendLoginAlert() already catches every failure
            // internally and always resolves (see utils/emailService.js), and
            // the response below must not wait on a round trip to an
            // external SMTP server.
            sendLoginAlert(user.email, ipAddress);

            res.json({ success: true, message: "Login successful!", role: user.role, token });
        } else {
            try {
                await Promise.all([
                    prisma.loginAttempt.create({
                        data: { userEmail: email, userId: user?.id ?? null, ipAddress, status: 'FAILED' }
                    }),
                    prisma.behaviorLog.create({
                        data: { userEmail: email, userId: user?.id ?? null, eventType: 'LOGIN_FAILED', description: 'Invalid password attempted.' }
                    })
                ]);
             } catch (logErr) {
                console.error("Audit log write failed on failed login:", logErr.message);
            }

            res.status(401).json({ success: false, message: "Invalid email or password." });
        }
    } catch (err) {
        console.error("Database query error:", err);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}
