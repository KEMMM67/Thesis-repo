import jwt from "jsonwebtoken";
import prisma from "../config/prisma.js";

/**
 * Verifies the `Authorization: Bearer <token>` header and attaches the
 * decoded identity to `req.user`.
 *
 * A cryptographically valid JWT is necessary but not sufficient: after the
 * signature check, this also confirms the corresponding Session row still
 * exists and has not expired. Without that check, a JWT stays valid until
 * its natural expiry regardless of server-side action, making it
 * impossible to force a specific device logged out early (see
 * `POST /api/admin/blocked-devices/unblock` and the dashboard's
 * "Force Logout / Revoke" control). Deleting the Session row is true
 * server-side revocation - the token continues to verify, but no longer
 * has a session backing it.
 *
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 * @returns {Promise<void>} Responds 401 on missing/invalid/revoked auth; otherwise calls `next()`.
 */
export async function authMiddleware(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

    if (!token) {
        return res.status(401).json({ success: false, message: "Authentication required." });
    }

    let decoded;
    try {
        // Explicitly restrict to the one algorithm this app ever signs
        // with (see controllers/authController.js), rather than trusting
        // whatever `alg` the token's own header claims - a token forged
        // with a different algorithm is rejected outright instead of
        // being evaluated on the signer's terms.
        decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    } catch (err) {
        return res.status(401).json({ success: false, message: "Invalid or expired token." });
    }

    try {
        const session = await prisma.session.findUnique({ where: { sessionToken: token } });
        if (!session || session.expiresAt <= new Date()) {
            return res.status(401).json({ success: false, message: "Session has been revoked or expired. Please log in again." });
        }
    } catch (err) {
        console.error("Session lookup failed during auth:", err.message);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }

    req.user = { email: decoded.email, role: decoded.role };
    next();
}

/**
 * Restricts a route to the given roles. Must be mounted after
 * `authMiddleware`, as it depends on `req.user`.
 *
 * @param {...string} allowedRoles - Roles permitted to access the route.
 * @returns {import("express").RequestHandler} Middleware responding 403 if `req.user.role` is not in `allowedRoles`.
 */
export function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ success: false, message: "Insufficient permissions." });
        }
        next();
    };
}
