import { describe, it, expect, vi } from 'vitest';
import { ALGORITHM_BY_ID } from './algorithms.js';
import { SCENARIO_BY_KEY } from './scenarios.js';
import { simulate, summarize } from './simulator.js';

/**
 * @fileoverview Checks that the comparison harness (bench/) measures the
 * algorithms it claims to: that simulated WEVA reproduces the numbers WEVA
 * documents for itself (core/scorer.js worked examples, the k6 defense run
 * in loadtest/), that express-rate-limit and the lockout behave as
 * configured, and that runs cannot leak state into one another. If any of
 * these fail, the published comparison (npm run bench:compare) cannot be
 * trusted until they pass again.
 */
vi.mock('@prisma/client', () => {
    throw new Error('The comparison harness must never load Prisma or reach a database.');
});

const run = async (scenarioKey, algorithmId, params) =>
    summarize(await simulate(SCENARIO_BY_KEY[scenarioKey], ALGORITHM_BY_ID[algorithmId], { params }));

describe('simulated WEVA matches WEVA\'s own documented behavior', () => {
    it('paced bot: 4 password checks, THROTTLE at attempt 5, BLOCK at attempt 8 (core/scorer.js worked example)', async () => {
        const { attack } = await run('paced', 'weva');
        expect(attack).toMatchObject({ reached: 4, firstRefusedAttempt: 5, firstBlockAttempt: 8 });
    });

    it('rotating device IDs on one IP: 4 password checks per 30 s through the IP layer, throttled, never blocked (core/ipAttempts.js)', async () => {
        const { attack } = await run('rotating', 'weva');
        // 60 s of guessing: 4 in the first window, 4 more as they age out.
        expect(attack).toMatchObject({ reached: 8, firstRefusedAttempt: 5, firstBlockAttempt: null });
    });

    it('a campus on one IP does not lock itself out: the scenario-6 cascade stays fixed', async () => {
        const { legit } = await run('campus-nat', 'weva', { students: 400 });
        expect(legit.usersDenied).toBeLessThan(20);
    });

    it('burst: the 3rd simultaneous guess is blocked on speed (middleware/securityMiddleware.js)', async () => {
        const { attack } = await run('burst', 'weva');
        expect(attack).toMatchObject({ reached: 2, firstRefusedAttempt: 3, firstBlockAttempt: 3 });
    });

    it('stolen admin token rotating device IDs: blocked account-wide from its 3rd request', async () => {
        const { attack } = await run('stolen-token', 'weva');
        expect(attack).toMatchObject({ reached: 2, firstBlockAttempt: 3 });
    });

    it('a guess every 35 s from rotating IDs stays under the 30 s IP window - the documented limit', async () => {
        const { attack } = await run('low-and-slow', 'weva');
        expect(attack.reached).toBe(attack.sent);
    });
});

describe('the baselines behave as configured', () => {
    it('fixed window (strict) lets 5 failures through per IP, then refuses', async () => {
        const { attack } = await run('paced', 'fw-strict');
        expect(attack).toMatchObject({ reached: 5, firstRefusedAttempt: 6 });
    });

    it('fixed window (strict) never counts successful requests', async () => {
        const { legit } = await run('bulk-grades', 'fw-strict');
        expect(legit).toMatchObject({ refused: 0, usersDenied: 0 });
    });

    it('fixed window (lenient) lets 100 requests through per IP, then refuses', async () => {
        const { attack } = await run('paced', 'fw-lenient');
        expect(attack).toMatchObject({ reached: 100, firstRefusedAttempt: 101 });
    });

    it('a simultaneous burst is counted one request at a time, as separate HTTP requests are', async () => {
        const { attack } = await run('burst', 'fw-strict');
        expect(attack).toMatchObject({ reached: 5, firstRefusedAttempt: 6 });
    });

    it('account lockout locks after 3 failures - and then refuses the real owner too', async () => {
        const paced = await run('paced', 'lockout');
        expect(paced.attack).toMatchObject({ reached: 3, firstRefusedAttempt: 4 });
        const dos = await run('lockout-dos', 'lockout');
        expect(dos.legit).toMatchObject({ users: 1, usersDenied: 1 });
    });
});

describe('runs are isolated and repeatable', () => {
    it('a run starts from a clean slate: a blocked attacker in one run is unknown to the next', async () => {
        const first = await run('paced', 'weva');
        const second = await run('paced', 'weva');
        expect(second).toEqual(first);
    });

    it('the same seed gives the same students, typos and results every time', async () => {
        const first = await run('campus-nat', 'weva', { students: 100 });
        const second = await run('campus-nat', 'weva', { students: 100 });
        expect(second).toEqual(first);
    });
});
