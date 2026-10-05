import { test, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALGORITHMS } from './algorithms.js';
import { SCENARIOS, PATIENCE_MS, MAX_REFUSALS } from './scenarios.js';
import { simulate, summarize, DEFAULT_SEED, SIM_EPOCH } from './simulator.js';

/**
 * @fileoverview The WEVA comparison: every scenario in bench/scenarios.js
 * against every algorithm in bench/algorithms.js, in simulated time
 * (bench/simulator.js). Writes public/data/weva-comparison.json, which
 * public/compare.html reads.
 *
 * Run it with `npm run bench:compare` - through vitest (bench/vitest.config.js),
 * because the simulator relies on vitest's fake timers and module resets.
 * It is not part of `npm test`: the file name does not end in .test.js.
 * The checks that the simulator reproduces WEVA's documented behavior are
 * in bench/harness.test.js, which is part of `npm test`.
 *
 * Nothing here touches a database. The algorithms run against in-memory
 * stores, and the mock below makes any attempt to load Prisma fail the run
 * outright - so a future import that happened to reach config/prisma.js
 * could never quietly connect to whatever DATABASE_URL points at.
 */
vi.mock('@prisma/client', () => {
    throw new Error('The comparison harness must never load Prisma or reach a database.');
});

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUTPUT = path.join(ROOT, 'public', 'data', 'weva-comparison.json');

/**
 * The two totals behind the trade-off chart. Attack: requests that got
 * through - guesses that reached the password check, deletions that ran -
 * in every scenario that has an attacker to stop. Legitimate: requests
 * refused in every scenario that has legitimate users to serve. Scenario 6
 * counts at its default campus size; the sweep shows the other sizes.
 */
const TRADEOFF = {
    attack: ['paced', 'burst', 'rotating', 'stolen-token', 'low-and-slow'],
    legit: ['lockout-dos', 'campus-nat', 'bulk-grades']
};

/**
 * A run's requests, compacted for the Scenario Replay: [time in tenths of a
 * second, outcome]. Outcomes: 0 attack got through, 1 attack stopped,
 * 2 legitimate request served, 3 legitimate request refused.
 */
function replayLane(records) {
    return records.map(r => [Math.round(r.t / 100), r.role === 'attack' ? (r.reached ? 0 : 1) : (r.reached ? 2 : 3)]);
}

/**
 * Prints a table to the terminal. Written straight to stdout: vitest does
 * not show console.log output from this run.
 *
 * @param {string} title
 * @param {string[]} header
 * @param {string[][]} rows
 * @returns {void}
 */
function printTable(title, header, rows) {
    const widths = header.map((cell, i) => Math.max(cell.length, ...rows.map(row => String(row[i]).length)));
    const line = (cells) => cells.map((cell, i) => String(cell).padEnd(widths[i])).join('  |  ');
    process.stdout.write(`\n${title}\n${line(header)}\n${widths.map(w => '-'.repeat(w)).join('--+--')}\n${rows.map(line).join('\n')}\n`);
}

/** @returns {{requests: number, medianMicros: number, p95Micros: number}} */
function costOf(samples) {
    const sorted = [...samples].sort((a, b) => a - b);
    const at = (q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
    return { requests: sorted.length, medianMicros: Number(at(0.5).toFixed(1)), p95Micros: Number(at(0.95).toFixed(1)) };
}

test('WEVA against fixed-window and account-lockout baselines, eight scenarios', async () => {
    // Taken before any simulation starts, so it is the real time.
    const generatedAt = new Date().toISOString();
    const guardMicros = Object.fromEntries(ALGORITHMS.map(algorithm => [algorithm.id, []]));
    const scenarios = [];

    for (const scenario of SCENARIOS) {
        const results = {};
        const lanes = {};
        let durationMs = 0;
        for (const algorithm of ALGORITHMS) {
            const run = await simulate(scenario, algorithm);
            results[algorithm.id] = summarize(run);
            lanes[algorithm.id] = replayLane(run.records);
            durationMs = Math.max(durationMs, run.durationMs);
            guardMicros[algorithm.id].push(...run.guardMicros);
        }

        let sweep;
        if (scenario.sweep) {
            sweep = [];
            for (const students of scenario.sweep) {
                const row = { students, results: {} };
                for (const algorithm of ALGORITHMS) {
                    row.results[algorithm.id] = summarize(await simulate(scenario, algorithm, { params: { students } })).legit;
                }
                sweep.push(row);
            }
        }

        const { id, key, title, tests, description, measures, params } = scenario;
        scenarios.push({ id, key, title, tests, description, measures, params, results, replay: { durationMs, lanes }, ...(sweep && { sweep }) });
    }

    const byKey = Object.fromEntries(scenarios.map(scenario => [scenario.key, scenario]));
    const tradeoff = {
        definition: {
            attackThrough: `Attack requests that got through, summed over scenarios ${TRADEOFF.attack.map(k => byKey[k].id).join(', ')}.`,
            legitRefused: `Legitimate requests refused, summed over scenarios ${TRADEOFF.legit.map(k => byKey[k].id).join(', ')} (scenario 6 at ${byKey['campus-nat'].params.students} students).`
        },
        points: ALGORITHMS.map(algorithm => {
            const attack = TRADEOFF.attack.map(k => ({ scenario: byKey[k].id, value: byKey[k].results[algorithm.id].attack.reached }));
            const legit = TRADEOFF.legit.map(k => ({ scenario: byKey[k].id, value: byKey[k].results[algorithm.id].legit.refused }));
            return {
                algorithm: algorithm.id,
                attackThrough: attack.reduce((sum, part) => sum + part.value, 0),
                legitRefused: legit.reduce((sum, part) => sum + part.value, 0),
                usersDenied: TRADEOFF.legit.reduce((sum, k) => sum + byKey[k].results[algorithm.id].legit.usersDenied, 0),
                breakdown: { attack, legit }
            };
        })
    };

    // The tuning every WEVA run used - the shipped defaults, since
    // simulate() clears SECURITY_* overrides before each run.
    const { securityConfig } = await import('../config/securityConfig.js');
    const { defaultWevaConfig } = await import('../core/scorer.js');
    const rateLimitPackage = JSON.parse(fs.readFileSync(path.join(ROOT, 'node_modules', 'express-rate-limit', 'package.json'), 'utf8'));

    const report = {
        format: 'weva-comparison/v1',
        generatedAt,
        command: 'npm run bench:compare',
        environment: {
            node: process.version,
            expressRateLimit: rateLimitPackage.version,
            seed: DEFAULT_SEED,
            simulatedStart: new Date(SIM_EPOCH).toISOString(),
            legitimateUsers: { patienceSeconds: PATIENCE_MS / 1000, maxRefusals: MAX_REFUSALS },
            weva: {
                windowMs: securityConfig.windowMs,
                emaAlpha: securityConfig.emaAlpha,
                thresholds: securityConfig.thresholds,
                adminTolerance: 15,
                blockMs: securityConfig.mitigation.temporaryBlockMs,
                minVelocityFloor: defaultWevaConfig.minVelocityFloor,
                failRateIncrement: defaultWevaConfig.failRateIncrement,
                velocityPointScale: defaultWevaConfig.velocityPointScale
            }
        },
        algorithms: ALGORITHMS.map(({ id, label, summary, config }) => ({ id, label, summary, config })),
        scenarios,
        tradeoff,
        // The guard's own decision time, in process, with in-memory
        // storage. Not end-to-end latency: in production WEVA's cost is
        // dominated by its database reads and audit writes - see the k6
        // results (loadtest/) for that.
        decisionCost: Object.fromEntries(ALGORITHMS.map(algorithm => [algorithm.id, costOf(guardMicros[algorithm.id])]))
    };

    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(report));

    // ---- Console summary ----
    const cell = (scenario, id) => {
        const { attack, legit } = scenario.results[id];
        const parts = [];
        if (attack) parts.push(`${attack.reached}/${attack.sent} through`);
        if (legit) parts.push(`${legit.refused} refused, ${legit.usersDenied}/${legit.users} denied`);
        return parts.join(' | ');
    };
    const labels = ALGORITHMS.map(algorithm => algorithm.label);
    printTable(
        `WEVA comparison - ${scenarios.length} scenarios x ${ALGORITHMS.length} algorithms (seed ${DEFAULT_SEED})`,
        ['Scenario', ...labels],
        scenarios.map(scenario => [`${scenario.id}. ${scenario.title}`, ...ALGORITHMS.map(algorithm => cell(scenario, algorithm.id))])
    );
    printTable(
        'Campus sweep (scenario 6) - students denied sign-in',
        ['Students', ...labels],
        byKey['campus-nat'].sweep.map(row => [row.students, ...ALGORITHMS.map(algorithm => row.results[algorithm.id].usersDenied)])
    );
    printTable(
        'Trade-off (lower is better on both)',
        ['Algorithm', 'Attack requests through', 'Legit requests refused', 'Legit users denied'],
        tradeoff.points.map(point => [ALGORITHMS.find(algorithm => algorithm.id === point.algorithm).label, point.attackThrough, point.legitRefused, point.usersDenied])
    );
    process.stdout.write(`\nWritten to ${path.relative(ROOT, OUTPUT)}\n\n`);
}, 10 * 60 * 1000);
