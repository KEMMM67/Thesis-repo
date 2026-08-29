// Central configuration file for adjusting the framework's security parameters
export const securityConfig = {
    windowMs: Number(process.env.SECURITY_WINDOW_MS) || 30000,
    emaAlpha: Number(process.env.SECURITY_EMA_ALPHA) || 0.1,

    // System Action Thresholds
    thresholds: {
        suspicious: Number(process.env.SECURITY_THRESHOLD_SUSPICIOUS) || 25,
        critical: Number(process.env.SECURITY_THRESHOLD_CRITICAL) || 60,
        block: Number(process.env.SECURITY_THRESHOLD_BLOCK) || 85
    },

    mitigation: {
        temporaryBlockMs: Number(process.env.SECURITY_MITIGATION_BLOCK_MS) || 60000
    }
};