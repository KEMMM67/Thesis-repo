import { securityConfig } from "../config/securityConfig.js";

// Stores the established behavioral baselines for individual users
const baselines = {};

// Retrieves the user's historical baseline profile or initializes a default one
export function getBaseline(user) {
    if (!baselines[user]) {
        baselines[user] = {
            requestRate: 0,
            previousScore: 0
        };
    }
    return baselines[user];
}

// Adaptive Exponential Moving Average (EMA) Learning
// Dynamically adjusts the user's baseline profile based on legitimate behavior over time
export function updateBaseline(user, currentFeatures) {
    const baseline = getBaseline(user);
    
    // The 'alpha' constant determines the system's learning rate sensitivity
    const alpha = securityConfig.emaAlpha || 0.1;

    // EMA Formula: Incorporates new behavior while retaining historical context
    baseline.requestRate = (currentFeatures.requestRate * alpha) + (baseline.requestRate * (1 - alpha));
}