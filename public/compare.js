console.log('[compare] Script parsed. Waiting for DOMContentLoaded...');

document.addEventListener('DOMContentLoaded', () => {
    console.log('[compare] DOMContentLoaded fired. Wiring simulation buttons...');

    /**
     * Prepends a timestamped message to the given log panel.
     *
     * @param {string} elementId - Target log container's id.
     * @param {string} message - Message to log.
     * @returns {void}
     */
    function addLog(elementId, message) {
        const logDiv = document.getElementById(elementId);
        logDiv.innerHTML = `<span>[${new Date().toLocaleTimeString()}] ${message}</span>` + logDiv.innerHTML;
    }

    /**
     * Updates a status box's text and styling state.
     *
     * @param {string} id - Target status box's id.
     * @param {string} text - Status text to display.
     * @param {string} state - Style variant (e.g. "blocked", "warning", "allowed").
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
    // ALGORITHM 3: ADAPTIVE EMA (simplified demo of the WEVA baseline
    // model implemented in core/profiler.js and core/scorer.js)
    // ---------------------------------------------------------------
    let emaClicks = [];
    let baselineSpeed = 0;
    let emaScore = 0;

    /**
     * Simulates a login attempt scored against a learned, adaptive baseline
     * (Exponential Moving Average) rather than a fixed rule. The score
     * rises sharply on a sudden deviation from the learned baseline, and
     * decays otherwise, illustrating why an EMA-based approach can
     * tolerate a legitimately fast user while still flagging a sudden
     * burst.
     */
    function testEMA() {
        const now = Date.now();
        emaClicks.push(now);
        const btn = document.getElementById('btn-ema');

        // Sliding window (1.5s, shortened for a live demo).
        emaClicks = emaClicks.filter(t => now - t < 1500);
        let currentSpeed = emaClicks.length;

        // EMA formula: the baseline adapts toward the current speed,
        // weighted 20% toward the newest observation.
        baselineSpeed = (currentSpeed * 0.2) + (baselineSpeed * 0.8);

        // Penalize a sudden deviation above baseline; forgive otherwise.
        let speedDiff = currentSpeed - baselineSpeed;
        if (speedDiff > 2) {
            emaScore += (speedDiff * 20);
        } else {
            emaScore -= 5;
        }

        if (emaScore < 0) emaScore = 0;
        if (emaScore > 100) emaScore = 100;

        if (emaScore >= 80) {
            setStatus('status-ema', `BLOCK (Score: ${Math.round(emaScore)})`, 'blocked');
            btn.disabled = true;
            addLog('log-ema', `CRITICAL: Sudden spike. Anomaly Score reached ${Math.round(emaScore)}.`);
        } else if (emaScore >= 40) {
            setStatus('status-ema', `THROTTLE (Score: ${Math.round(emaScore)})`, 'warning');
            addLog('log-ema', `WARNING: Suspicious speed detected.`);
        } else {
            setStatus('status-ema', `ALLOW (Score: ${Math.round(emaScore)})`, 'allowed');
            addLog('log-ema', `Learned baseline: ${baselineSpeed.toFixed(1)}. Speed is natural.`);
        }
    }

    document.getElementById('btn-trad').addEventListener('click', testTraditional);
    document.getElementById('btn-rule').addEventListener('click', testRuleBased);
    document.getElementById('btn-ema').addEventListener('click', testEMA);

    console.log('[compare] Simulation buttons wired successfully.');
});
