import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { computeScore, DEFAULT_SCORING } from '../lib/scorer.js';
import { decideAction } from '../lib/decision.js';

const config = { ...DEFAULT_SCORING, endpointWeights: { '/api/login': 2, '/api/students/view': 1, '/api/students/:id': 3 } };
const score = (requestRate, loginAttempts, endpoint) => computeScore({ requestRate, loginAttempts, endpoint }, { requestRate: 0 }, config);

test('reproduces the worked examples of the thesis build (core/scorer.test.js)', () => {
    assert.equal(score(0, 0, '/api/students/view').score, 0);    // idle browsing
    assert.equal(score(3, 0, '/api/students/view').score, 15);   // +3 req/s on a 1x route
    assert.equal(score(3, 0, '/api/students/:id').score, 45);    // the same burst on a 3x route
    assert.equal(score(0, 4, '/api/login').score, 60);           // 5th login attempt: THROTTLE
    assert.equal(score(0, 6, '/api/login').score, 80);           // 7th: still THROTTLE
    assert.equal(score(0, 7, '/api/login').score, 90);           // 8th: the first BLOCK
    assert.equal(score(0, 8, '/api/login').score, 100);          // 9th: clamped at 100
});

test('itemizes every factor, so each verdict can be audited', () => {
    assert.deepEqual(score(0, 4, '/api/login').breakdown, {
        velocityIncrement: 2,
        endpointWeight: 2,
        failRateFactor: 3,
        scale: 5,
        formula: '2 x 2 x 3 x 5 = 60'
    });
});

test('maps scores to verdicts at 25 / 60 / 85', () => {
    assert.deepEqual(
        [0, 24, 25, 59, 60, 84, 85, 100].map(s => decideAction(s)),
        ['ALLOW', 'ALLOW', 'LOG', 'LOG', 'THROTTLE', 'THROTTLE', 'BLOCK', 'BLOCK']
    );
});

// Runs only inside the thesis repository, where this package sits in packages/.
const thesisScorer = new URL('../../../core/scorer.js', import.meta.url);
const thesisDecisionEngine = new URL('../../../core/decisionEngine.js', import.meta.url);

test('gives the same score, breakdown and verdict as the thesis build\'s core/', { skip: !existsSync(thesisScorer) && 'not inside the thesis repository' }, async () => {
    const thesis = await import(thesisScorer);
    const { decideAction: thesisDecide } = await import(thesisDecisionEngine);
    const sameTuning = { ...DEFAULT_SCORING, endpointWeights: thesis.defaultWevaConfig.endpointWeights };

    let compared = 0;
    for (const endpoint of [...Object.keys(thesis.defaultWevaConfig.endpointWeights), '/api/unlisted']) {
        for (const requestRate of [0, 0.4, 1, 2.5, 3, 7.25, 20, 2000]) {
            for (const baselineRate of [0, 0.5, 3]) {
                for (let loginAttempts = 0; loginAttempts <= 10; loginAttempts++) {
                    const current = { requestRate, loginAttempts, endpoint };
                    const baseline = { requestRate: baselineRate };
                    const expected = thesis.computeScore(current, baseline);

                    assert.deepEqual(computeScore(current, baseline, sameTuning), expected);
                    assert.equal(decideAction(expected.score), thesisDecide(expected.score, 'guest'));
                    compared++;
                }
            }
        }
    }
    assert.ok(compared > 4000, `compared ${compared} inputs`);
});
