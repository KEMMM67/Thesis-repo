import { seededRandom } from './simulator.js';

/**
 * @fileoverview The eight scenarios of the WEVA comparison
 * (bench/run-comparison.js). Each one isolates one property a static
 * limiter lacks, or - scenario 8 - one WEVA documents as out of its reach.
 *
 * A scenario's cast() returns its actors. An actor is a script: a generator
 * that yields `{ after, send }` - wait `after` milliseconds, then send these
 * requests at the same instant - and receives one result per request:
 * `{ reached, status, retryAfterMs }` (bench/simulator.js). Attackers keep
 * their pace whatever happens, as bots do. Legitimate users react the way
 * people do: a typo gets retyped, and a refusal is retried after the wait
 * the server asks for - unless it asks for longer than PATIENCE_MS, or has
 * refused them MAX_REFUSALS times, at which point they give up.
 *
 * Every actor draws from its own random stream, seeded once from the
 * scenario's seed when the cast is created. So under every algorithm the
 * same students arrive at the same moments and make the same typos, and a
 * student refused under one algorithm cannot shift anyone else's draws.
 *
 * Addresses come from the documentation ranges (RFC 5737), and every
 * timing is a parameter, recorded in the results file next to the results.
 */

const SECOND = 1000;
const MINUTE = 60 * SECOND;

/** A legitimate user gives up when told to wait longer than this... */
export const PATIENCE_MS = 2 * MINUTE;
/** ...or after being refused this many times. */
export const MAX_REFUSALS = 3;

const ATTACKER_IP = '203.0.113.66';
const CAMPUS_IP = '198.51.100.10';
const VICTIM_HOME_IP = '192.0.2.44';
const REGISTRAR_IP = '198.51.100.20';
const VICTIM = 'student@example.edu.ph';
const REGISTRAR = 'registrar@example.edu.ph';

/** @returns {{goal: number, achieved: number, refusals: number, startedAt: number|null, finishedAt: number|null}} */
const newReport = (goal) => ({ goal, achieved: 0, refusals: 0, startedAt: null, finishedAt: null });

/** A login attempt from an attacker: always the wrong password. */
const guess = (ip, deviceId, email = VICTIM) => ({ kind: 'login', email, ip, deviceId, correctPassword: false });

/**
 * An attacker that sends `makeRequests(i)` every `intervalMs`, `count`
 * times, whatever comes back.
 */
function bot(label, count, intervalMs, makeRequests, startAfterMs = 0) {
    return {
        role: 'attack',
        label,
        script: function* () {
            for (let i = 0; i < count; i++) {
                yield { after: i === 0 ? startAfterMs : intervalMs, send: makeRequests(i) };
            }
        }
    };
}

/**
 * A legitimate user signing in once. A typo is noticed and retyped 3-8 s
 * later; a refusal is retried after the wait the server gives, plus up to
 * 2 s - within the limits at the top of this file.
 */
function student({ label, email, ip, deviceId, arriveAfterMs, mistype, rng, clock }) {
    const report = newReport(1);
    return {
        role: 'legit',
        label,
        report,
        script: function* () {
            let wait = arriveAfterMs;
            let correctPassword = !mistype;
            for (;;) {
                const [result] = yield { after: wait, send: [{ kind: 'login', email, ip, deviceId, correctPassword }] };
                report.startedAt ??= clock.now();
                if (result.reached && result.status === 200) {
                    report.achieved = 1;
                    report.finishedAt = clock.now();
                    return;
                }
                if (result.reached) {
                    correctPassword = true;
                    wait = 3 * SECOND + rng() * 5 * SECOND;
                    continue;
                }
                report.refusals += 1;
                const told = result.retryAfterMs ?? 15 * SECOND;
                if (report.refusals >= MAX_REFUSALS || told > PATIENCE_MS) return;
                wait = told + rng() * 2 * SECOND;
            }
        }
    };
}

/** @type {object[]} */
export const SCENARIOS = [
    {
        id: 1,
        key: 'paced',
        title: 'Paced brute force',
        tests: 'Failure memory',
        description: 'One bot, one device and one IP guesses a student\'s password every half second.',
        measures: 'attack',
        params: { guesses: 120, intervalMs: 500 },
        cast: ({ guesses, intervalMs }) => [
            bot('Paced bot', guesses, intervalMs, () => [guess(ATTACKER_IP, 'DEV-pacedbot')])
        ]
    },
    {
        id: 2,
        key: 'burst',
        title: 'Burst',
        tests: 'Speed against the device\'s own baseline',
        description: 'One device fires 10 guesses at the same instant, every 3 seconds.',
        measures: 'attack',
        params: { bursts: 10, burstSize: 10, intervalMs: 3000 },
        cast: ({ bursts, burstSize, intervalMs }) => [
            bot('Burst bot', bursts, intervalMs, () => Array.from({ length: burstSize }, () => guess(ATTACKER_IP, 'DEV-burstbot')))
        ]
    },
    {
        id: 3,
        key: 'rotating',
        title: 'Rotating device ID',
        tests: 'IP layer',
        description: 'One bot on one IP sends a brand-new device ID with every guess, every half second.',
        measures: 'attack',
        params: { guesses: 120, intervalMs: 500 },
        cast: ({ guesses, intervalMs }) => [
            bot('Rotating bot', guesses, intervalMs, (i) => [guess(ATTACKER_IP, `DEV-rot-${i}`)])
        ]
    },
    {
        id: 4,
        key: 'lockout-dos',
        title: 'Lockout as denial of service',
        tests: 'Who pays for an attack',
        description: 'An attacker fails 3 times on a student\'s account from their own network; 30 s later the real student signs in from home with the right password.',
        measures: 'both',
        params: { attackerGuesses: 3, attackerIntervalMs: 2000, victimArrivesAfterMs: 30 * SECOND },
        cast: ({ attackerGuesses, attackerIntervalMs, victimArrivesAfterMs }, rng, clock) => [
            bot('Attacker', attackerGuesses, attackerIntervalMs, () => [guess(ATTACKER_IP, 'DEV-attacker')]),
            student({
                label: 'The real student', email: VICTIM, ip: VICTIM_HOME_IP, deviceId: 'DEV-victimlaptop',
                arriveAfterMs: victimArrivesAfterMs, mistype: false, rng: seededRandom(Math.floor(rng() * 2 ** 32)), clock
            })
        ]
    },
    {
        id: 5,
        key: 'stolen-token',
        title: 'Stolen admin session',
        tests: 'Account layer and endpoint weight',
        description: 'A script holding a stolen admin token deletes student records 20 times a second, with a new device ID on every request.',
        measures: 'attack',
        params: { deletes: 200, intervalMs: 50 },
        cast: ({ deletes, intervalMs }) => [
            bot('Stolen-token script', deletes, intervalMs, (i) => [{
                kind: 'admin', method: 'DELETE', route: '/api/students/:id',
                path: `/api/students/CC25-${String(i + 1).padStart(6, '0')}`,
                ip: ATTACKER_IP, deviceId: `DEV-stolen-${i}`, actorEmail: REGISTRAR, role: 'admin'
            }])
        ]
    },
    {
        id: 6,
        key: 'campus-nat',
        title: 'Campus behind one IP',
        tests: 'False positives on a shared address',
        description: 'Enrollment opens: students sign in over 5 minutes, all behind the campus NAT\'s single public IP; 1 in 10 mistypes their password once.',
        measures: 'legit',
        params: { students: 400, arrivalWindowMs: 5 * MINUTE, typoRate: 0.1 },
        sweep: [50, 100, 200, 400, 800, 1600, 3200],
        cast: ({ students, arrivalWindowMs, typoRate }, rng, clock) => Array.from({ length: students }, (_, i) => {
            const own = seededRandom(Math.floor(rng() * 2 ** 32));
            return student({
                label: `Student ${i + 1}`, email: `student${i + 1}@campus.edu.ph`, ip: CAMPUS_IP, deviceId: `DEV-campus-${i + 1}`,
                arriveAfterMs: Math.floor(own() * arrivalWindowMs), mistype: own() < typoRate, rng: own, clock
            });
        })
    },
    {
        id: 7,
        key: 'bulk-grades',
        title: 'Registrar posting grades',
        tests: 'False positives on heavy, legitimate admin work',
        description: 'A registrar saves 150 grades for three sections, one every 1-2 seconds.',
        measures: 'legit',
        params: { saves: 150, meanIntervalMs: 1500, jitterMs: 500 },
        cast: ({ saves, meanIntervalMs, jitterMs }, rng, clock) => {
            const own = seededRandom(Math.floor(rng() * 2 ** 32));
            const report = newReport(saves);
            return [{
                role: 'legit',
                label: 'Registrar',
                report,
                script: function* () {
                    let wait = 0;
                    let refusedThisSave = 0;
                    while (report.achieved < saves) {
                        const [result] = yield {
                            after: wait,
                            send: [{
                                kind: 'admin', method: 'PUT', route: '/api/grades/:id', path: `/api/grades/${1000 + report.achieved}`,
                                ip: REGISTRAR_IP, deviceId: 'DEV-registrar', actorEmail: REGISTRAR, role: 'admin'
                            }]
                        };
                        report.startedAt ??= clock.now();
                        if (result.reached) {
                            report.achieved += 1;
                            report.finishedAt = clock.now();
                            refusedThisSave = 0;
                            wait = meanIntervalMs + (own() * 2 - 1) * jitterMs;
                            continue;
                        }
                        // Refused: retry the same save after the wait the
                        // server gives - or stop, with the rest unsaved, if
                        // that wait is beyond a person's patience or the
                        // same save keeps being refused.
                        report.refusals += 1;
                        refusedThisSave += 1;
                        const told = result.retryAfterMs ?? 15 * SECOND;
                        if (told > PATIENCE_MS || refusedThisSave >= MAX_REFUSALS) return;
                        wait = told + own() * 2 * SECOND;
                    }
                }
            }];
        }
    },
    {
        id: 8,
        key: 'low-and-slow',
        title: 'Low and slow, rotating IDs',
        tests: 'A limit WEVA documents (core/ipAttempts.js)',
        description: 'One bot on one IP guesses every 35 seconds for half an hour, with a new device ID each time - just outside WEVA\'s 30-second IP window.',
        measures: 'attack',
        params: { guesses: 52, intervalMs: 35 * SECOND },
        cast: ({ guesses, intervalMs }) => [
            bot('Slow rotating bot', guesses, intervalMs, (i) => [guess(ATTACKER_IP, `DEV-slow-${i}`)])
        ]
    }
];

/** @type {Record<string, object>} */
export const SCENARIO_BY_KEY = Object.fromEntries(SCENARIOS.map(scenario => [scenario.key, scenario]));
