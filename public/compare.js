// WEVA's production scoring function - the very file the server runs
// (core/scorer.js, served at /weva/scorer.js by server.js). Importing it,
// rather than re-implementing the formula here, is what keeps card 3 honest:
// it cannot show a different formula from the one that scores real logins.
import { computeScore } from '/weva/scorer.js';

console.log('[compare] Module loaded. Wiring simulation buttons...');

/**
 * Prepends a timestamped line to the given log panel. Built with
 * textContent rather than innerHTML, like the rest of the frontend.
 *
 * @param {string} elementId - Target log container's id.
 * @param {string} message - Message to log.
 * @returns {void}
 */
function addLog(elementId, message) {
    const line = document.createElement('span');
    line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    document.getElementById(elementId).prepend(line);
}

/**
 * Updates a status box's text and styling state.
 *
 * @param {string} id - Target status box's id.
 * @param {string} text - Status text to display.
 * @param {string} state - Style variant ("blocked", "warning", "logged", "allowed", or "" for neutral).
 * @returns {void}
 */
function setStatus(id, text, state) {
    const box = document.getElementById(id);
    box.innerText = text;
    box.className = `status-box ${state}`;
}

// ---------------------------------------------------------------
// ALGORITHM 1: TRADITIONAL SECURITY (fixed attempt limit)
// ---------------------------------------------------------------
let tradAttempts = 0;

/** Simulates a login attempt against a static 3-attempt lockout rule. */
function testTraditional() {
    tradAttempts++;
    const btn = document.getElementById('btn-trad');

    if (tradAttempts >= 3) {
        setStatus('status-trad', 'BLOCKED: Exceeded 3 Attempts', 'blocked');
        btn.disabled = true;
        addLog('log-trad', 'Account permanently locked.');
    } else {
        setStatus('status-trad', `FAILED: Attempt ${tradAttempts}/3`, 'warning');
        addLog('log-trad', 'Invalid login attempt.');
    }
}

// ---------------------------------------------------------------
// ALGORITHM 2: RULE-BASED SECURITY (static request-rate limit)
// ---------------------------------------------------------------
let ruleClicks = [];

/** Simulates a login attempt against a static clicks-per-second limit. */
function testRuleBased() {
    const now = Date.now();
    ruleClicks.push(now);
    const btn = document.getElementById('btn-rule');

    ruleClicks = ruleClicks.filter(t => now - t < 1000);

    if (ruleClicks.length > 2) {
        setStatus('status-rule', 'BLOCKED: Speed Limit Exceeded', 'blocked');
        btn.disabled = true;
        addLog('log-rule', `Detected ${ruleClicks.length} clicks/sec. Static rule broken.`);
    } else {
        setStatus('status-rule', 'ALLOW: Speed Normal', 'allowed');
        addLog('log-rule', 'Login processed.');
    }
}

// ---------------------------------------------------------------
// ALGORITHM 3: WEVA (Weighted Endpoint & Velocity Algorithm)
// ---------------------------------------------------------------
// Every score below comes from computeScore() - the production function.
// Around it, this card reproduces what the server does for one device
// sending failed attempts to POST /api/login (weight 2x), using
// config/securityConfig.js's defaults:
//   - core/monitor.js: request rate across the last 30 s, and the count
//     of prior login attempts;
//   - core/profiler.js: the device's EMA baseline rate (alpha 0.1);
//   - core/decisionEngine.js: thresholds for a request that is not signed
//     in yet (LOG 25, THROTTLE 60, BLOCK 85, no role tolerance);
//   - core/mitigation.js: a BLOCK locks the device out for 60 s.
// If those files change, change these values with them.
const WEVA_WINDOW_MS = 30000;
const WEVA_EMA_ALPHA = 0.1;
const WEVA_THRESHOLDS = { suspicious: 25, critical: 60, block: 85 };
const WEVA_BLOCK_MS = 60000;
const LOGIN_ENDPOINT = '/api/login';

const device = { requests: [], loginAttempts: 0, baselineRate: 0 };
let wevaAttempt = 0;

/**
 * @param {number} score - 0-100 anomaly score.
 * @returns {"BLOCK"|"THROTTLE"|"LOG"|"ALLOW"}
 */
function decide(score) {
    if (score >= WEVA_THRESHOLDS.block) return 'BLOCK';
    if (score >= WEVA_THRESHOLDS.critical) return 'THROTTLE';
    if (score >= WEVA_THRESHOLDS.suspicious) return 'LOG';
    return 'ALLOW';
}

/**
 * Scores one failed login attempt in the same order as
 * middleware/securityMiddleware.js: read the device's current features,
 * score them against its baseline, then record the attempt.
 *
 * @param {number} now - Epoch milliseconds of the attempt.
 * @returns {{score: number, breakdown: {formula: string}, decision: string}}
 */
function scoreAttempt(now) {
    device.requests = device.requests.filter(t => now - t < WEVA_WINDOW_MS);
    const requestRate = device.requests.length > 1
        ? (device.requests.length / Math.max(now - device.requests[0], 1)) * 1000
        : 0;

    const result = computeScore(
        { requestRate, loginAttempts: device.loginAttempts, endpoint: LOGIN_ENDPOINT },
        { requestRate: device.baselineRate }
    );

    device.requests.push(now);
    device.loginAttempts += 1;
    device.baselineRate = requestRate * WEVA_EMA_ALPHA + device.baselineRate * (1 - WEVA_EMA_ALPHA);

    return { ...result, decision: decide(result.score) };
}

/**
 * Disables the button for the lockout and counts it down, as
 * core/mitigation.js's temporary block does. The device keeps its attempt
 * history, so once the lockout lifts, its next failed attempt is still
 * scored against every earlier one.
 *
 * @param {HTMLButtonElement} button
 * @param {number} until - Epoch milliseconds when the block lifts.
 * @returns {void}
 */
function holdForBlock(button, until) {
    const idleLabel = button.textContent;
    button.disabled = true;

    const tick = () => {
        const left = Math.ceil((until - Date.now()) / 1000);
        if (left > 0) {
            button.textContent = `Blocked: ${left}s left`;
            return;
        }
        clearInterval(timer);
        button.disabled = false;
        button.textContent = idleLabel;
        setStatus('status-weva', 'BLOCK LIFTED (attempt history kept)', '');
        addLog('log-weva', 'Temporary block lifted. The next attempt is still scored with every earlier failure.');
    };
    const timer = setInterval(tick, 250);
    tick();
}

/** Simulates one failed login attempt against WEVA. */
function testWeva() {
    const now = Date.now();
    const btn = document.getElementById('btn-weva');
    const { score, breakdown, decision } = scoreAttempt(now);
    wevaAttempt++;
    const line = `Attempt ${wevaAttempt}: ${breakdown.formula} -> ${decision}`;

    if (decision === 'BLOCK') {
        setStatus('status-weva', `BLOCK (Score: ${score})`, 'blocked');
        addLog('log-weva', `${line}. Device locked out for ${WEVA_BLOCK_MS / 1000} s.`);
        holdForBlock(btn, now + WEVA_BLOCK_MS);
    } else if (decision === 'THROTTLE') {
        setStatus('status-weva', `THROTTLE (Score: ${score})`, 'warning');
        addLog('log-weva', `${line}. Request refused (HTTP 429).`);
    } else if (decision === 'LOG') {
        setStatus('status-weva', `LOG (Score: ${score})`, 'logged');
        addLog('log-weva', `${line}. Allowed, flagged in the audit log.`);
    } else {
        setStatus('status-weva', `ALLOW (Score: ${score})`, 'allowed');
        addLog('log-weva', `${line}. Allowed.`);
    }
}

document.getElementById('btn-trad').addEventListener('click', testTraditional);
document.getElementById('btn-rule').addEventListener('click', testRuleBased);
document.getElementById('btn-weva').addEventListener('click', testWeva);

console.log('[compare] Simulation buttons wired successfully.');
