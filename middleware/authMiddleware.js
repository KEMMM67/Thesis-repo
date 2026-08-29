import jwt from "jsonwebtoken";

// Verifies the Authorization: Bearer <token> header and attaches the
// decoded identity to req.user. Rejects with 401 if missing/invalid.
export function authMiddleware(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

    if (!token) {
        return res.status(401).json({ success: false, message: "Authentication required." });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { email: decoded.email, role: decoded.role };
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: "Invalid or expired token." });
    }
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