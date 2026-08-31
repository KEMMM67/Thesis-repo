import jwt from "jsonwebtoken";
import prisma from "../config/prisma.js";

// Verifies the Authorization: Bearer <token> header and attaches the
// decoded identity to req.user. Rejects with 401 if missing/invalid.
//
// A cryptographically valid JWT is necessary but no longer sufficient:
// after verifying the signature, this also confirms the Session row
// this exact token corresponds to still exists and hasn't expired.
// Without that second check, a JWT is valid until it naturally expires
// no matter what - there would be no way to force a specific device
// logged out early (see POST /api/admin/blocked-devices/unblock and the
// dashboard's "Force Logout / Revoke" button). Deleting that row is
// true server-side revocation; the token itself keeps verifying fine,
// it just no longer has a session backing it.
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
        decoded = jwt.verify(token, process.env.JWT_SECRET);
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

// Gate a route to specific roles. Must run after authMiddleware.
export function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ success: false, message: "Insufficient permissions." });
        }
        next();
    };
}
