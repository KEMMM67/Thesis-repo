// WEVA defense simulation: 3 legitimate students keep using the system while
// three kinds of bot attack the login, one after another. Run from the repo root:
//   k6 run -e BASE_URL=https://thesis-repo-8swh.onrender.com loadtest/weva-defense-test.js
// Optional -e overrides: LEGIT_VUS, PACED_VUS, BURST_VUS, ROTATE_VUS, ATTACK_SLEEP,
// BURST_SIZE, BURST_PAUSE_S, BASELINE_S, PACED_S, BURST_S, ROTATE_S, GAP_S,
// RECOVERY_S, TARGET_EMAIL, LEGIT_EMAIL, LEGIT_PASSWORD, LEGIT_P95_MS, SUMMARY_JSON.
// Legit users log in from loadtest/accounts.json (prisma/seed-loadtest-accounts.js)
// when it exists, otherwise as LEGIT_EMAIL (default: the seeded demo student).
//
// The attacks run in sequence, not together: all bots share this machine's IP, and
// WEVA's IP layer (core/ipAttempts.js) would merge them into one attacker. GAP_S of
// quiet between attacks lets that IP's 30 s attempt window empty, so each attack
// demonstrates one WEVA factor on its own. The rotating attack runs last because it
// ends with this IP throttled until its last guesses are 30 s old - wait half a
// minute before re-running.

import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';
import { Counter, Rate, Trend } from 'k6/metrics';

const BASE_URL = (__ENV.BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');
const LEGIT_VUS = intEnv('LEGIT_VUS', 3);
const PACED_VUS = intEnv('PACED_VUS', 1);
const BURST_VUS = intEnv('BURST_VUS', 1);
const ROTATE_VUS = intEnv('ROTATE_VUS', 1);
const ATTACK_SLEEP = numEnv('ATTACK_SLEEP', 0.5);
const BURST_SIZE = intEnv('BURST_SIZE', 10);
const BURST_PAUSE_S = numEnv('BURST_PAUSE_S', 3);
const BASELINE_S = intEnv('BASELINE_S', 20);
const PACED_S = intEnv('PACED_S', 30);
const BURST_S = intEnv('BURST_S', 10);
const ROTATE_S = intEnv('ROTATE_S', 30);
const GAP_S = intEnv('GAP_S', 35);
const RECOVERY_S = intEnv('RECOVERY_S', 30);
const TARGET_EMAIL = __ENV.TARGET_EMAIL || 'student@example.edu.ph';
const LEGIT_P95_MS = intEnv('LEGIT_P95_MS', 3000);

const PACED_START = BASELINE_S;
const BURST_START = PACED_START + PACED_S + GAP_S;
const ROTATE_START = BURST_START + BURST_S + GAP_S;
const ATTACK_END = ROTATE_START + ROTATE_S;
const TOTAL_S = ATTACK_END + RECOVERY_S;

// POST /api/login's floor-regime score per core/scorer.js defaultWevaConfig
// (velocity floor 2 x endpoint weight 2 x point scale 5, fail-rate +0.5 per prior
// attempt) against config/securityConfig.js thresholds. Only used to print the
// formula's prediction next to what was observed.
const FLOOR_SCORE = 2 * 2 * 5;
const FAIL_RATE_STEP = 0.5;
const THROTTLE_THRESHOLD = intEnv('THROTTLE_THRESHOLD', 60);
const BLOCK_THRESHOLD = intEnv('BLOCK_THRESHOLD', 85);

const pool = new SharedArray('legit-accounts', function () {
  try {
    const file = JSON.parse(open('./accounts.json'));
    return file.emails.map(function (email) {
      return { email: email, password: file.password };
    });
  } catch (_) {
    return [{ email: __ENV.LEGIT_EMAIL || 'student@example.edu.ph', password: __ENV.LEGIT_PASSWORD || 'student123' }];
  }
});

const legitLatency = new Trend('legit_latency_ms', true);
const legitSuccess = new Rate('legit_success');
const attackStopped = new Rate('attack_stopped_by_weva');
const throttled = new Counter('weva_throttle_429');
const blocked = new Counter('weva_block_403');
const unexpected = new Counter('unexpected_responses');
const wevaRejectLatency = new Trend('weva_reject_latency_ms', true);
const passwordCheckLatency = new Trend('password_check_latency_ms', true);
const legitNetworkErrors = new Counter('legit_network_errors');
const attackNetworkErrors = new Counter('attack_network_errors');

const bots = {
  paced: botMetrics('paced'),
  burst: botMetrics('burst'),
  rotating: botMetrics('rotating'),
};

function botMetrics(kind) {
  return {
    checks: new Counter(`${kind}_password_checks`),
    leaks: new Counter(`${kind}_leaks_after_detection`),
    untilThrottle: new Trend(`${kind}_attempts_until_throttle`),
    untilBlock: new Trend(`${kind}_attempts_until_block`),
    secondsToBlock: new Trend(`${kind}_seconds_until_block`),
  };
}

function botScenario(vus, fn, startS, durationS) {
  return { executor: 'constant-vus', exec: fn, vus: vus, startTime: `${startS}s`, duration: `${durationS}s`, gracefulStop: '5s' };
}

const scenarios = {
  legit_users: { executor: 'constant-vus', exec: 'legitUser', vus: LEGIT_VUS, duration: `${TOTAL_S}s` },
};
const thresholds = {
  unexpected_responses: ['count==0'],
};
['baseline', 'attack', 'recovery'].forEach(function (phase) {
  thresholds[`legit_success{phase:${phase}}`] = ['rate>0.99'];
  thresholds[`legit_latency_ms{phase:${phase}}`] = [`p(95)<${LEGIT_P95_MS}`];
});
// The password-check caps are the thesis claims: a paced attack gets the 4 guesses
// before THROTTLE, a burst gets 2. A rotating attack is seen only by the IP layer,
// which throttles but never blocks (core/ipAttempts.js): at most 4 guesses in any
// 30 s, so 4 per started 30 s of the attack, counting k6's 5 s graceful stop.
// Its guesses that pass after the first THROTTLE are that allowance, not leaks.
if (PACED_VUS > 0) {
  scenarios.paced_bot = botScenario(PACED_VUS, 'pacedBot', PACED_START, PACED_S);
  thresholds.paced_password_checks = [`count<=${predictedAttempt(THROTTLE_THRESHOLD) - 1}`];
  thresholds.paced_leaks_after_detection = ['count==0'];
}
if (BURST_VUS > 0) {
  scenarios.burst_bot = botScenario(BURST_VUS, 'burstBot', BURST_START, BURST_S);
  thresholds.burst_password_checks = [`count<=${2 * BURST_VUS}`];
  thresholds.burst_leaks_after_detection = ['count==0'];
}
if (ROTATE_VUS > 0) {
  scenarios.rotating_bot = botScenario(ROTATE_VUS, 'rotatingBot', ROTATE_START, ROTATE_S);
  thresholds.rotating_password_checks = [`count<=${(predictedAttempt(THROTTLE_THRESHOLD) - 1) * Math.ceil((ROTATE_S + 5) / 30)}`];
}

export const options = {
  setupTimeout: '5m',
  batch: Math.max(BURST_SIZE, 20),
  batchPerHost: Math.max(BURST_SIZE, 20),
  scenarios: scenarios,
  thresholds: thresholds,
};

export function setup() {
  // Zero samples so the count thresholds are evaluated even when nothing goes wrong.
  unexpected.add(0);
  Object.keys(bots).forEach(function (kind) {
    bots[kind].checks.add(0);
    bots[kind].leaks.add(0);
  });

  const warm = http.get(`${BASE_URL}/`, { timeout: '120s', tags: { traffic: 'setup' } });
  if (warm.status !== 200) {
    exec.test.abort(`Warm-up GET ${BASE_URL}/ returned HTTP ${warm.status} - check BASE_URL and that the service is up.`);
  }

  const runId = `k6-${Date.now().toString(36)}`;
  const sessions = [];
  const count = Math.min(LEGIT_VUS, pool.length);
  for (let i = 0; i < count; i++) {
    const account = pool[i];
    const deviceId = `${runId}-user-${i + 1}`;
    const res = http.post(`${BASE_URL}/api/login`, JSON.stringify({ email: account.email, password: account.password }), {
      headers: { 'Content-Type': 'application/json', 'x-device-id': deviceId },
      timeout: '60s',
      tags: { traffic: 'setup' },
    });
    const body = parseBody(res);
    if (res.status === 403 || res.status === 429) {
      exec.test.abort(`Legit login refused by WEVA (HTTP ${res.status}) - this machine's IP is still throttled or blocked from a previous run. Wait a minute and retry.`);
    }
    if (res.status !== 200 || !body || !body.token) {
      exec.test.abort(`Legit login failed for ${account.email} (HTTP ${res.status}): ${String(res.body).slice(0, 160)} - legit users must be seeded student accounts.`);
    }
    sessions.push({ token: body.token, deviceId: deviceId });
  }

  return { runId: runId, sessions: sessions, t0: Date.now() };
}

// GET /api/students/me is authenticated but not WEVA-scored, so it measures whether
// the attacks degrade service for real users - and it decrypts their AES-256-GCM
// grades on every call, so a FIELD_ENCRYPTION_KEY mismatch surfaces here as failures.
export function legitUser(data) {
  const session = data.sessions[(exec.vu.idInTest - 1) % data.sessions.length];
  const res = http.get(`${BASE_URL}/api/students/me`, {
    headers: { Authorization: `Bearer ${session.token}`, 'x-device-id': session.deviceId },
    timeout: '30s',
    tags: { traffic: 'legit' },
  });

  if (neverReachedServer(res)) {
    legitNetworkErrors.add(1);
    sleep(3 + Math.random() * 2);
    return;
  }

  const tags = { phase: phaseAt(Date.now() - data.t0) };
  const body = parseBody(res);
  const ok = res.status === 200 && body !== null && body.success === true;
  legitSuccess.add(ok, tags);
  legitLatency.add(res.timings.duration, tags);
  if (!ok) unexpected.add(1, { traffic: 'legit', status: String(res.status) });

  sleep(3 + Math.random() * 2);
}

// Kept per bot kind, not per VU: k6 reuses one VU across scenarios that don't
// overlap in time, so the same VU can run the paced, burst and rotating attacks.
const botStates = {};

function botState(kind, data) {
  if (!botStates[kind]) {
    botStates[kind] = { deviceId: `${data.runId}-${kind}-${exec.vu.idInTest}`, attempts: 0, bursts: 0, startedAt: Date.now(), throttledAt: 0, blockedAt: 0 };
  }
  return botStates[kind];
}

// One stable device ID, one guess every ATTACK_SLEEP seconds: below the velocity
// floor, so the fail-rate factor alone escalates it.
export function pacedBot(data) {
  sequentialAttack(data, 'paced', function (state) { return state.deviceId; });
}

// A brand-new x-device-id on every guess: the device layer never sees history,
// so only the IP layer can stop it.
export function rotatingBot(data) {
  sequentialAttack(data, 'rotating', function (state, attempt) { return `${state.deviceId}-${attempt}`; });
}

function sequentialAttack(data, kind, deviceIdFor) {
  const state = botState(kind, data);
  const attempt = state.attempts + 1;
  const outcome = tally(http.post(`${BASE_URL}/api/login`, loginBody(), attackParams(deviceIdFor(state, attempt), kind)));
  // WEVA never saw an attempt that never reached the server, so it doesn't
  // advance the attempt count the escalation ladder is measured against.
  if (outcome === 'network') {
    sleep(ATTACK_SLEEP);
    return;
  }
  state.attempts = attempt;
  const metrics = bots[kind];

  if (outcome === 'password_check') {
    metrics.checks.add(1);
    if (state.throttledAt || state.blockedAt) metrics.leaks.add(1);
  } else if (outcome === 'throttle' && !state.throttledAt) {
    state.throttledAt = state.attempts;
    metrics.untilThrottle.add(state.attempts);
  } else if (outcome === 'block' && !state.blockedAt) {
    state.blockedAt = state.attempts;
    metrics.untilBlock.add(state.attempts);
    metrics.secondsToBlock.add((Date.now() - state.startedAt) / 1000);
  }

  sleep(ATTACK_SLEEP);
}

// BURST_SIZE guesses sent simultaneously from one stable device ID: velocity far
// above the device's EMA baseline, so the speed term blocks the 3rd request.
export function burstBot(data) {
  const state = botState('burst', data);
  state.bursts += 1;

  const requests = [];
  for (let i = 0; i < BURST_SIZE; i++) {
    requests.push({ method: 'POST', url: `${BASE_URL}/api/login`, body: loginBody(), params: attackParams(state.deviceId, 'burst') });
  }
  const checks = http.batch(requests).map(tally).filter(function (outcome) { return outcome === 'password_check'; }).length;

  bots.burst.checks.add(checks);
  if (state.bursts > 1 && checks > 0) bots.burst.leaks.add(checks);

  sleep(BURST_PAUSE_S);
}

function loginBody() {
  return JSON.stringify({ email: TARGET_EMAIL, password: `guess-${Math.random().toString(36).slice(2, 10)}` });
}

function attackParams(deviceId, kind) {
  return { headers: { 'Content-Type': 'application/json', 'x-device-id': deviceId }, timeout: '30s', tags: { traffic: 'attack', bot: kind } };
}

// Attributes a response by WEVA's own bodies (core/mitigation.js), not status code
// alone, so a 403/429 from the hosting edge is never credited to WEVA.
function tally(res) {
  if (neverReachedServer(res)) {
    attackNetworkErrors.add(1);
    return 'network';
  }

  const body = parseBody(res);
  const message = body && typeof body.message === 'string' ? body.message : '';
  let outcome = 'unexpected';
  if (res.status === 403 && message.indexOf('CRITICAL THREAT') === 0) outcome = 'block';
  else if (res.status === 429 && message.indexOf('Too many attempts') === 0) outcome = 'throttle';
  else if (res.status === 401) outcome = 'password_check';

  attackStopped.add(outcome === 'throttle' || outcome === 'block');
  if (outcome === 'password_check') {
    passwordCheckLatency.add(res.timings.duration);
  } else if (outcome === 'throttle') {
    throttled.add(1);
    wevaRejectLatency.add(res.timings.duration);
  } else if (outcome === 'block') {
    blocked.add(1);
    wevaRejectLatency.add(res.timings.duration);
  } else {
    unexpected.add(1, { traffic: 'attack', status: String(res.status) });
  }
  return outcome;
}

export function handleSummary(data) {
  const outputs = { stdout: buildReport(data) };
  outputs[__ENV.SUMMARY_JSON || 'loadtest/weva-defense-summary.json'] = JSON.stringify(data, null, 2);
  return outputs;
}

function buildReport(data) {
  const metrics = data.metrics;
  const get = function (name, stat) {
    const m = metrics[name];
    return m && m.values && m.values[stat] !== undefined ? m.values[stat] : null;
  };
  const count = function (name) { return get(name, 'count') || 0; };
  const pct = function (v) { return v === null ? 'n/a' : `${(v * 100).toFixed(1)}%`; };
  const ms = function (v) { return v === null ? 'n/a' : `${Math.round(v)} ms`; };
  const med = function (name) { const v = get(name, 'med'); return v === null ? 'n/a' : String(Math.round(v * 10) / 10); };
  const col = function (s) { return String(s).padEnd(14); };

  const throttleAt = predictedAttempt(THROTTLE_THRESHOLD);
  const blockAt = predictedAttempt(BLOCK_THRESHOLD);
  const guesses = (get('attack_stopped_by_weva', 'passes') || 0) + (get('attack_stopped_by_weva', 'fails') || 0);

  const lines = [
    '',
    '======================= WEVA DEFENSE REPORT =======================',
    `${BASE_URL} | ${LEGIT_VUS} legit users | bots: ${PACED_VUS} paced, ${BURST_VUS} burst, ${ROTATE_VUS} rotating-ID | under attack ${PACED_START}s-${ATTACK_END}s`,
  ];

  const ladder = function (kind, title, how) {
    lines.push(
      '',
      `${title} - ${how}`,
      `  Reached the password check : ${count(`${kind}_password_checks`)}   (formula: ${throttleAt - 1})`,
      `  First THROTTLE / BLOCK     : attempt #${med(`${kind}_attempts_until_throttle`)} / #${med(`${kind}_attempts_until_block`)}   (formula: #${throttleAt} / #${blockAt}), blocked ${med(`${kind}_seconds_until_block`)}s in`,
      `  Leaks after detection      : ${count(`${kind}_leaks_after_detection`)}`
    );
  };
  if (PACED_VUS > 0) ladder('paced', 'PACED BRUTE FORCE', `one device ID, a guess every ${ATTACK_SLEEP}s (fail-rate factor + velocity floor)`);
  if (BURST_VUS > 0) {
    const leaked = count('burst_leaks_after_detection');
    lines.push(
      '',
      `BURST - ${BURST_SIZE} simultaneous guesses from one device ID (velocity vs. EMA baseline)`,
      `  Reached the password check : ${count('burst_password_checks') - leaked} of ${BURST_SIZE} in the first burst   (formula: 2 - the 3rd is blocked on speed)`,
      `  Leaks in later bursts      : ${leaked}`
    );
  }
  if (ROTATE_VUS > 0) {
    lines.push(
      '',
      'ROTATING DEVICE ID - a new x-device-id on every guess (IP layer: throttles, never blocks)',
      `  Reached the password check : ${count('rotating_password_checks')}   (formula: at most ${throttleAt - 1} in any 30 s)`,
      `  First THROTTLE             : attempt #${med('rotating_attempts_until_throttle')}   (formula: #${throttleAt})`,
      `  Passed after first THROTTLE: ${count('rotating_leaks_after_detection')}   (guesses let through as earlier ones aged out of the 30 s window)`
    );
  }

  lines.push(
    '',
    `All attack traffic: ${guesses} guesses, ${pct(get('attack_stopped_by_weva', 'rate'))} stopped before the password check (429: ${count('weva_throttle_429')} | 403: ${count('weva_block_403')})`,
    // Medians, not p95: the burst's simultaneous requests queue behind each other,
    // which inflates the rejection tail without saying anything about per-request cost.
    `Median latency: WEVA rejection ${ms(get('weva_reject_latency_ms', 'med'))} | password-check path ${ms(get('password_check_latency_ms', 'med'))}`,
    '',
    `LEGITIMATE USERS              ${col('baseline')}${col('under attack')}${col('recovery')}`,
    `  Success rate                ${['baseline', 'attack', 'recovery'].map(function (p) { return col(pct(get(`legit_success{phase:${p}}`, 'rate'))); }).join('')}`,
    `  p95 latency                 ${['baseline', 'attack', 'recovery'].map(function (p) { return col(ms(get(`legit_latency_ms{phase:${p}}`, 'p(95)'))); }).join('')}`,
    '',
    `Never reached the server (client network errors, excluded above): ${count('legit_network_errors')} legit, ${count('attack_network_errors')} attack`,
    `Unexpected / non-WEVA responses: ${count('unexpected_responses')}`,
    '',
    'THRESHOLDS'
  );

  Object.keys(metrics).sort().forEach(function (name) {
    const results = metrics[name].thresholds;
    if (!results) return;
    Object.keys(results).forEach(function (expr) {
      lines.push(`  ${results[expr].ok ? 'PASS' : 'FAIL'}  ${name}  ${expr}`);
    });
  });

  lines.push('====================================================================', '');
  return lines.join('\n');
}

// Smallest attempt n whose floor-regime score FLOOR_SCORE x (1 + 0.5(n-1)) reaches the threshold.
function predictedAttempt(threshold) {
  for (let n = 2; n <= 100; n++) {
    if (FLOOR_SCORE * (1 + FAIL_RATE_STEP * (n - 1)) >= threshold) return n;
  }
  return 100;
}

// k6 error codes 1100-1399 are DNS, TCP and TLS failures (a Windows "connectex"
// connect timeout is 1213): the request never reached the app, so it says nothing
// about the app or WEVA. A request that connected and then timed out (1050) still
// counts as a failure.
function neverReachedServer(res) {
  return res.status === 0 && res.error_code >= 1100 && res.error_code < 1400;
}

function parseBody(res) {
  try {
    return res.json();
  } catch (_) {
    return null;
  }
}

function phaseAt(elapsedMs) {
  if (elapsedMs < PACED_START * 1000) return 'baseline';
  if (elapsedMs < ATTACK_END * 1000) return 'attack';
  return 'recovery';
}

function intEnv(name, fallback) {
  const v = parseInt(__ENV[name], 10);
  return Number.isFinite(v) ? v : fallback;
}

function numEnv(name, fallback) {
  const v = parseFloat(__ENV[name]);
  return Number.isFinite(v) ? v : fallback;
}
