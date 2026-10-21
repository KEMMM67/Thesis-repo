import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import express from 'express';
import { wevaSecurity, MemoryBlockStore } from 'weva-security';

/**
 * Every test runs a real Express app over HTTP, with Date mocked so that
 * "one guess per second" is exact rather than dependent on timing.
 */
const START = Date.parse('2026-10-21T08:00:00Z');

async function startApp(t, options = {}) {
    t.mock.timers.enable({ apis: ['Date'], now: START });

    const evaluations = [];
    const app = express();
    app.set('trust proxy', 'loopback');   // lets a test pick its client IP with X-Forwarded-For
    app.use(express.json());
    app.use(wevaSecurity({
        authPaths: ['/api/login'],
        endpointWeights: { '/api/students/:id': 3 },
        onEvaluation: evaluation => evaluations.push(evaluation),
        ...options
    }));
    app.post('/api/login', (req, res) => {
        if (req.body.password !== 'right') return res.status(401).json({ success: false });
        req.weva.loginSucceeded(req.body.email);
        res.json({ success: true });
    });
    app.get('/api/login', (req, res) => res.send('login page'));
    app.delete('/api/students/:id', (req, res) => res.json({ success: true }));
    app.get('/style.css', (req, res) => res.type('css').send('body {}'));

    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => {
        server.closeAllConnections();
        server.close();
    });
    return { url: `http://127.0.0.1:${server.address().port}`, evaluations };
}

async function send(url, { method = 'POST', path = '/api/login', device, ip = '203.0.113.7', email = 'student@example.edu', password = 'wrong' } = {}) {
    const headers = { 'content-type': 'application/json', 'x-forwarded-for': ip };
    if (device) headers['x-device-id'] = device;
    const body = method === 'GET' ? undefined : JSON.stringify({ email, password });
    const res = await fetch(url + path, { method, headers, body });
    await res.text();
    return res;
}

/** Sends `count` requests one simulated second apart; `request` may depend on the index. */
async function sendEverySecond(t, url, count, request) {
    const responses = [];
    for (let i = 0; i < count; i++) {
        responses.push(await send(url, typeof request === 'function' ? request(i) : request));
        t.mock.timers.tick(1000);
    }
    return responses;
}

const statuses = responses => responses.map(res => res.status);

test('a guessing device gets 401 four times, then 429 with Retry-After: 15, then 403 on the 8th guess', async t => {
    const { url, evaluations } = await startApp(t);

    const responses = await sendEverySecond(t, url, 8, { device: 'DEV-attacker' });

    assert.deepEqual(statuses(responses), [401, 401, 401, 401, 429, 429, 429, 403]);
    assert.deepEqual(responses.map(res => res.headers.get('retry-after')), [null, null, null, null, '15', '15', '15', '60']);
    assert.deepEqual(evaluations.map(e => e.score), [0, 30, 40, 50, 60, 70, 80, 90]);
    assert.equal(evaluations[4].breakdown.formula, '2 x 2 x 3 x 5 = 60');
});

test('a block holds against the right password, lands only on that device, and goes to the injected store', async t => {
    const blockStore = new MemoryBlockStore();
    const { url } = await startApp(t, { blockStore });

    await sendEverySecond(t, url, 8, { device: 'DEV-attacker' });

    assert.equal((await send(url, { device: 'DEV-attacker', password: 'right' })).status, 403);
    assert.equal((await blockStore.findStatus('DEV-attacker')).isBlocked, true);
    // A student on another network signs in normally.
    assert.equal((await send(url, { device: 'DEV-student', ip: '198.51.100.20', password: 'right' })).status, 200);
});

test('rotating device IDs does not reset the count: the IP layer throttles the 5th guess', async t => {
    const { url, evaluations } = await startApp(t);

    const responses = await sendEverySecond(t, url, 5, i => ({ device: `DEV-rotating-${i}` }));

    assert.deepEqual(statuses(responses), [401, 401, 401, 401, 429]);
    assert.equal(evaluations[4].decidedBy, 'ip');
    assert.deepEqual(evaluations[4].scores, { device: 0, ip: 60 });
});

test('a successful login settles the user\'s own typos', async t => {
    const { url, evaluations } = await startApp(t);

    await sendEverySecond(t, url, 2, { device: 'DEV-student' });
    await sendEverySecond(t, url, 1, { device: 'DEV-student', password: 'right' });
    await sendEverySecond(t, url, 1, { device: 'DEV-student' });

    assert.deepEqual(evaluations.map(e => e.score), [0, 30, 40, 0]);
});

test('signing into your own account does not erase your guesses at someone else\'s', async t => {
    const { url, evaluations } = await startApp(t);
    const guessAtVictim = { device: 'DEV-insider', email: 'victim@example.edu' };

    await sendEverySecond(t, url, 3, guessAtVictim);
    await sendEverySecond(t, url, 1, { device: 'DEV-insider', email: 'insider@example.edu', password: 'right' });
    const responses = await sendEverySecond(t, url, 2, guessAtVictim);

    assert.deepEqual(statuses(responses), [401, 429]);
    assert.deepEqual(evaluations.slice(-2).map(e => e.score), [50, 60]);
});

test('a burst is caught on its 3rd request: two others in the same millisecond read as 2000 req/s', async t => {
    const { url } = await startApp(t);

    const burst = await Promise.all([1, 2, 3].map(() => send(url, { method: 'DELETE', path: '/api/students/7', device: 'DEV-script' })));

    assert.deepEqual(statuses(burst).sort(), [200, 200, 403]);
});

test('"/API/Login/" counts as the same route as "/api/login", as it does for Express', async t => {
    const { url } = await startApp(t);

    const responses = await sendEverySecond(t, url, 5, { device: 'DEV-case', path: '/API/Login/' });

    assert.deepEqual(statuses(responses), [401, 401, 401, 401, 429]);
});

test('unlisted routes are not scored, and a GET of a login page is not a login attempt', async t => {
    const { url, evaluations } = await startApp(t);

    const assets = await Promise.all(Array.from({ length: 10 }, () => send(url, { method: 'GET', path: '/style.css' })));
    const loginPage = await sendEverySecond(t, url, 5, { method: 'GET', device: 'DEV-reader' });

    assert.ok(assets.every(res => res.status === 200));
    assert.deepEqual(statuses(loginPage), [200, 200, 200, 200, 200]);
    assert.equal(evaluations.length, 5);   // only the login page GETs were scored...
    assert.ok(evaluations.every(e => e.breakdown.failRateFactor === 1));   // ...and none as a failed login
});

test('a device ID shaped like an IP is ignored, so it cannot frame another address', async t => {
    const { url, evaluations } = await startApp(t);

    await send(url, { device: '198.51.100.99', ip: '203.0.113.7' });

    assert.equal(evaluations[0].deviceKey, '203.0.113.7');
});

test('rejects a broken configuration at startup', () => {
    assert.throws(() => wevaSecurity({ thresholds: { critical: 90 } }), /thresholds/);
    assert.throws(() => wevaSecurity({ endpointWeights: { '/api/x': 0 } }), /endpointWeights/);
    assert.throws(() => wevaSecurity({ blockStore: {} }), /blockStore/);
});
