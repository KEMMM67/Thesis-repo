import { describe, test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { wevaSecurity } from 'weva-security';

/**
 * @fileoverview Replays the same traffic through the thesis build's
 * production middleware (middleware/securityMiddleware.js with core/) and
 * through this package, and requires the same outcome for every request:
 * which identity decided (device or IP), the formula, score and verdict, the
 * HTTP status and the retry time. Production's retry time comes from its JSON
 * body, this package's from its Retry-After header.
 *
 * Both run in this process on one simulated clock with in-memory storage -
 * the method of the thesis build's own middleware/securityMiddleware.test.js
 * and bench/. The package runs on its defaults plus the thesis's routes and
 * endpoint weights. Every request is unauthenticated, as at a login page, so
 * the two parts of WEVA this package leaves out - the signed-in-account
 * identity and the admin tolerance - never come into play.
 *
 *   npm run test:parity
 */

const repoFile = path => new URL(`../../../${path}`, import.meta.url);
const inThesisRepo = existsSync(repoFile('middleware/securityMiddleware.js'));

const START = Date.UTC(2026, 9, 21, 8, 0, 0);
const MINUTE = 60_000;

// ---- The traffic ----------------------------------------------------------

/**
 * Each route as production mounts it (Express's matched route and mount
 * path) and as this package sees it under app.use() (the raw path).
 */
const ROUTES = {
    login: { method: 'POST', path: '/api/login', production: { baseUrl: '/api', path: '/login', route: { path: '/login' } } },
    otp: { method: 'POST', path: '/api/verify-otp', production: { baseUrl: '/api', path: '/verify-otp', route: { path: '/verify-otp' } } },
    delete: { method: 'DELETE', path: '/api/students/CC25-000001', production: { baseUrl: '', path: '/api/students/CC25-000001', route: { path: '/api/students/:id' } } },
    ping: { method: 'POST', path: '/api/demo/ping', production: { baseUrl: '', path: '/api/demo/ping', route: { path: '/api/demo/ping' } } }
};

const login = (device, ip, email, right = false) => ({ kind: 'login', device, ip, email, right });
const times = (count, make) => Array.from({ length: count }, (_, i) => make(i));
/** One request per step, `ms` apart. A step holding several requests sends them in the same millisecond. */
const every = (ms, requests) => requests.map(request => ({ requests: [request], thenWait: ms }));
const pause = ms => ({ requests: [], thenWait: ms });

const SCENARIOS = [
    {
        name: 'password guessing, one guess per second',
        showLadder: true,
        steps: every(1000, times(12, () => login('DEV-paced', '10.0.1.1', 'victim@x.edu')))
    },
    {
        name: 'password guessing, 300 ms apart',
        steps: every(300, times(12, () => login('DEV-fast', '10.0.2.1', 'victim@x.edu')))
    },
    {
        name: 'six guesses in the same millisecond',
        steps: [{ requests: times(6, () => login('DEV-burst', '10.0.3.1', 'victim@x.edu')), thenWait: 0 }]
    },
    {
        name: 'a new device ID with every guess, from one IP',
        steps: every(1000, times(10, i => login(`DEV-rotating-${i}`, '10.0.4.1', 'victim@x.edu')))
    },
    {
        name: 'guesses at a victim around a login to the attacker\'s own account',
        steps: every(1000, [
            ...times(3, () => login('DEV-insider', '10.0.5.1', 'victim@x.edu')),
            login('DEV-insider', '10.0.5.1', 'insider@x.edu', true),
            ...times(4, () => login('DEV-insider', '10.0.5.1', 'victim@x.edu'))
        ])
    },
    {
        name: 'two typos, then a correct login',
        steps: every(2000, [
            login('DEV-student', '10.0.6.1', 'student@x.edu'),
            login('DEV-student', '10.0.6.1', ' Student@X.edu'),
            login('DEV-student', '10.0.6.1', 'student@x.edu', true),
            login('DEV-student', '10.0.6.1', 'student@x.edu'),
            login('DEV-student', '10.0.6.1', 'student@x.edu', true)
        ])
    },
    {
        name: 'OTP guessing',
        steps: every(1500, times(9, () => ({ kind: 'otp', device: 'DEV-otp', ip: '10.0.7.1', email: 'admin@x.edu' })))
    },
    {
        name: 'a client that sends no device ID',
        steps: every(1000, times(10, () => login(null, '10.0.8.1', 'victim@x.edu')))
    },
    {
        name: 'block, expiry and re-block',
        steps: [
            ...every(1000, times(9, () => login('DEV-expiry', '10.0.9.1', 'victim@x.edu'))),
            pause(61_000),
            ...every(1000, times(3, () => login('DEV-expiry', '10.0.9.1', 'victim@x.edu')))
        ]
    },
    {
        name: 'a flood of DELETEs at 5 req/s on a 3x route',
        steps: every(200, times(40, () => ({ kind: 'delete', device: 'DEV-flood', ip: '10.0.10.1' })))
    },
    randomTraffic('random traffic, 8 seeds, 15% correct logins', [1, 2, 3, 4, 5, 6, 7, 8], 0.15, [0, 0, 1, 5, 40, 150, 400, 900, 1500, 3000, 12_000, 31_000]),
    randomTraffic('random traffic, 8 seeds, 50% correct logins', [11, 12, 13, 14, 15, 16, 17, 18], 0.5, [0, 5, 150, 900, 1500, 3000, 6000, 12_000, 31_000, 31_000])
];

/**
 * 250 steps per seed over four device IDs plus a client without one, two
 * IPs and three accounts: logins, OTPs, DELETEs and pings at random gaps,
 * with the occasional burst of 2-4 simultaneous copies. Deterministic, so a
 * failure always reproduces. Each seed uses its own devices and IPs and ends
 * with 31 idle minutes.
 */
function randomTraffic(name, seeds, correctRate, gaps) {
    const steps = [];
    for (const seed of seeds) {
        const random = mulberry32(seed);
        const pick = list => list[Math.floor(random() * list.length)];
        const devices = [...['a', 'b', 'c', 'd'].map(d => `DEV-${seed}-${d}`), null];
        const ips = [`10.${seed}.0.1`, `10.${seed}.0.2`];
        const accounts = ['a@x.edu', 'b@x.edu', 'c@x.edu'];
        for (let i = 0; i < 250; i++) {
            const roll = random();
            const kind = roll < 0.6 ? 'login' : roll < 0.7 ? 'otp' : roll < 0.85 ? 'delete' : 'ping';
            const correct = random() < correctRate;
            const request = { kind, device: pick(devices), ip: pick(ips), email: pick(accounts), right: correct && (kind === 'login' || kind === 'otp') };
            const copies = random() < 0.08 ? 2 + Math.floor(random() * 3) : 1;
            steps.push({ requests: times(copies, () => ({ ...request })), thenWait: pick(gaps) });
        }
        steps.push(pause(31 * MINUTE));
    }
    return { name, steps };
}

/** Small seeded PRNG (mulberry32). */
function mulberry32(seed) {
    return () => {
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

const requestCount = scenario => scenario.steps.reduce((sum, step) => sum + step.requests.length, 0);
const TOTAL = SCENARIOS.reduce((sum, scenario) => sum + requestCount(scenario), 0);
const formatCount = n => n.toLocaleString('en-US');

// ---- The replay -----------------------------------------------------------

/** A response object both can write to: production uses Express's res.status().json(), this package Node's res.setHeader()/res.end(). */
function fakeResponse(onFinish) {
    return {
        statusCode: 200,
        headers: {},
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; onFinish(); return this; },
        setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
        end(text) { this.body = JSON.parse(text); onFinish(); }
    };
}

/** What the host application answers when WEVA lets a request through. */
const appStatus = request => ((request.kind === 'login' || request.kind === 'otp') && !request.right ? 401 : 200);

/**
 * Production's audit row as the same fields as this package's evaluation.
 * Its `reason` reads "<Device|IP|Account> <key> triggered <VERDICT> on ... | <formula>".
 */
function fromAudit(row) {
    const separator = row.reason.lastIndexOf(' | ');
    const decidedBy = { Device: 'device', IP: 'ip', Account: 'account' }[row.reason.split(' ', 1)[0]];
    return { decidedBy, formula: row.reason.slice(separator + 3), score: row.score, verdict: row.actionTaken };
}

const fromEvaluation = evaluation => ({ decidedBy: evaluation.decidedBy, formula: evaluation.breakdown.formula, score: evaluation.score, verdict: evaluation.decision });

const deviceHeader = request => (request.device ? { 'x-device-id': request.device } : {});

describe(`weva-security vs the production middleware (middleware/securityMiddleware.js + core/): ${formatCount(TOTAL)} requests`, { skip: !inThesisRepo && 'not inside the thesis repository' }, () => {
    const audits = [];        // production's audit rows, one per request
    const evaluations = [];   // this package's evaluations, one per request
    let production;
    let settleProduction;
    let sdk;
    const totals = { requests: 0, differences: 0 };

    before(async () => {
        mock.timers.enable({ apis: ['Date'], now: START });
        mock.method(console, 'log', () => {});   // production logs every request

        const { createSecurityMiddleware } = await import(repoFile('middleware/securityMiddleware.js'));
        const { settleDeviceAttempts } = await import(repoFile('core/monitor.js'));
        const { settleIpAttempts } = await import(repoFile('core/ipAttempts.js'));
        const { getClientIdentity, normalizeAccount } = await import(repoFile('middleware/clientIdentity.js'));
        const { defaultWevaConfig } = await import(repoFile('core/scorer.js'));

        // In-memory versions of production's storage ports, as in bench/algorithms.js.
        const blocks = new Map();
        production = createSecurityMiddleware({
            auditSink: { recordEvaluation: async evaluation => { audits.push(evaluation); } },
            ipTrackingStore: {
                async findStatus(id) { return blocks.has(id) ? { ...blocks.get(id) } : null; },
                async block(id, blockedUntil) { blocks.set(id, { isBlocked: true, blockedUntil }); },
                async clear(id) { if (blocks.has(id)) blocks.set(id, { isBlocked: false, blockedUntil: null }); }
            },
            identityResolver: { resolve: async () => null }
        });
        // What controllers/authController.js#completeLogin does after a successful login.
        settleProduction = (req, email) => {
            const { ip, deviceKey } = getClientIdentity(req);
            settleDeviceAttempts(deviceKey, normalizeAccount(email));
            settleIpAttempts(ip, normalizeAccount(email));
        };

        sdk = wevaSecurity({
            authPaths: ['/api/login', '/api/verify-otp'],
            endpointWeights: defaultWevaConfig.endpointWeights,
            onEvaluation: evaluation => { evaluations.push(evaluation); }
        });
    });

    after(() => {
        mock.timers.reset();
        mock.restoreAll();
    });

    async function runProduction(request) {
        const route = ROUTES[request.kind];
        const req = { headers: deviceHeader(request), ip: request.ip, body: { email: request.email }, method: route.method, ...route.production };
        const res = fakeResponse(() => {});
        let passed = false;
        await production(req, res, () => { passed = true; });
        if (passed && request.right) settleProduction(req, request.email);
        return {
            status: passed ? appStatus(request) : res.statusCode,
            retry: res.body?.retryAfter ?? res.body?.retryAfterSeconds ?? null
        };
    }

    async function runSdk(request) {
        const route = ROUTES[request.kind];
        const req = { headers: deviceHeader(request), ip: request.ip, body: { email: request.email }, method: route.method, baseUrl: '', path: route.path, url: route.path };
        let res;
        const passed = await new Promise((resolve, reject) => {
            res = fakeResponse(() => resolve(false));
            sdk(req, res, err => (err ? reject(err) : resolve(true)));
        });
        if (passed && request.right) req.weva.loginSucceeded(request.email);
        const header = res.headers['retry-after'];
        const retry = header === undefined ? null : Number(header);
        assert.equal(res.body?.retryAfter ?? res.body?.retryAfterSeconds ?? null, retry, 'Retry-After header and JSON body disagree');
        return { status: passed ? appStatus(request) : res.statusCode, retry };
    }

    /** Sends one step's requests to both, production first, at the same simulated instant. */
    async function replay(requests) {
        const auditBase = audits.length;
        const productionResults = await Promise.all(requests.map(runProduction));
        const evaluationBase = evaluations.length;
        const sdkResults = await Promise.all(requests.map(runSdk));
        return requests.map((_, i) => ({
            production: { ...fromAudit(audits[auditBase + i]), ...productionResults[i] },
            sdk: { ...fromEvaluation(evaluations[evaluationBase + i]), ...sdkResults[i] }
        }));
    }

    for (const scenario of SCENARIOS) {
        test(`${scenario.name}: ${formatCount(requestCount(scenario))} requests`, async t => {
            const pairs = [];
            for (const step of scenario.steps) {
                pairs.push(...await replay(step.requests));
                if (step.thenWait) mock.timers.tick(step.thenWait);
            }

            const firstDifference = pairs.findIndex(pair => !isDeepStrictEqual(pair.production, pair.sdk));
            totals.requests += pairs.length;
            totals.differences += pairs.filter(pair => !isDeepStrictEqual(pair.production, pair.sdk)).length;
            if (scenario.showLadder) showLadder(t, pairs);

            assert.equal(firstDifference, -1, firstDifference === -1 ? '' :
                `request ${firstDifference + 1}: production ${JSON.stringify(pairs[firstDifference].production)}, weva-security ${JSON.stringify(pairs[firstDifference].sdk)}`);
        });
    }

    test(`all ${SCENARIOS.length} scenarios: ${formatCount(TOTAL)} of ${formatCount(TOTAL)} requests identical (deciding identity, formula, score, verdict, HTTP status, retry time)`, () => {
        assert.equal(totals.requests, TOTAL);
        assert.equal(totals.differences, 0);
    });
});

/** Prints both implementations' outcomes side by side, one column per request. */
function showLadder(t, pairs) {
    const row = values => values.map(value => String(value ?? '-').padEnd(4)).join('');
    const lines = [
        ['score', 'production', pair => pair.production.score],
        ['score', 'weva-security', pair => pair.sdk.score],
        ['HTTP', 'production', pair => pair.production.status],
        ['HTTP', 'weva-security', pair => pair.sdk.status],
        ['retry (s)', 'production', pair => pair.production.retry, '(JSON body)'],
        ['retry (s)', 'weva-security', pair => pair.sdk.retry, '(Retry-After header)']
    ];
    for (const [label, side, value, note = ''] of lines) {
        t.diagnostic(`${label.padEnd(10)}${side.padEnd(15)}${row(pairs.map(value))}${note}`);
    }
}
