import { securityConfig } from "../config/securityConfig.js";

// In-memory store for currently blocked users (Clears upon server restart)
const blockedList = new Map();

// Applies penalties based on the Decision Engine's verdict
export function applyMitigation(decision, res, identifier) {
    const now = Date.now();

    // Step 1: Verify if the user is currently serving a lockout penalty
    if (blockedList.has(identifier)) {
        const unblockTime = blockedList.get(identifier);
        
        if (now < unblockTime) {
            // Lockout period is still active; reject the request immediately
            res.status(403).json({
                success: false,
                message: "CRITICAL THREAT: Brute force behavior detected. IP temporarily blocked."
            });
            return true; 
        } else {
            // Lockout period expired; remove the user from the blacklist
            blockedList.delete(identifier);
        }
    }

    // Step 2: Enforce new penalties based on the current decision
    if (decision === 'BLOCK') {
        // Add user to the blacklist for the configured duration
        blockedList.set(identifier, now + securityConfig.mitigation.temporaryBlockMs);
        res.status(403).json({
            success: false,
            message: "CRITICAL THREAT: Brute force behavior detected. IP temporarily blocked."
        });
        return true;

    } else if (decision === 'THROTTLE') {
        // Issue a rate-limit warning and require a cooldown period
        res.status(429).json({
            success: false,
            message: "Too many attempts. Please wait.",
            retryAfter: 15
        });
        return true;
    }

    // ALLOW or LOG actions require no immediate mitigation; permit the request
    return false;
}