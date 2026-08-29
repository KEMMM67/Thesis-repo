import { securityConfig } from "../config/securityConfig.js";

// Evaluates the anomaly score against system thresholds to determine the security action
export function decideAction(score, role) {
    let blockThreshold = securityConfig.thresholds.block;       // Default: 85
    let throttleThreshold = securityConfig.thresholds.critical; // Default: 60
    let logThreshold = securityConfig.thresholds.suspicious;    // Default: 15

    // Role-Based Behavior Profiling: 
    // Grants higher tolerance thresholds for Administrators to accommodate bulk operations
    if (role === 'admin') {
        blockThreshold += 15;    
        throttleThreshold += 15; 
    }

    // Evaluate the score and return the corresponding mitigation decision
    if (score >= blockThreshold) {
        return 'BLOCK';
    } else if (score >= throttleThreshold) {
        return 'THROTTLE';
    } else if (score >= logThreshold) {
        return 'LOG';
    } else {
        return 'ALLOW';
    }
}