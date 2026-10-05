// WEVA's production scoring function - the very file the server runs
// (core/scorer.js, served at /weva/scorer.js by server.js). Importing it,
// rather than re-implementing the formula here, is what keeps the WEVA card
// in "Try it yourself" honest: it cannot show a different formula from the
// one that scores real logins.
import { computeScore } from '/weva/scorer.js';

/**
 * @fileoverview Algorithm Comparative Analysis page (public/compare.html).
 *
 * Three parts:
 *   1. Results - the trade-off chart and the scenario table, read from
 *      /data/weva-comparison.json, which `npm run bench:compare` writes
 *      (bench/run-comparison.js). Nothing on this page computes a result;
 *      it only displays the measured ones.
 *   2. Scenario Replay - plays a scenario's recorded requests back, one
 *      lane per algorithm, over a fixed ~14 seconds whatever the simulated
 *      duration.
 *   3. Try it yourself - three click-to-attack cards, simulated in the
 *      browser.
 *
 * All text from the results file is inserted with textContent, never as
 * HTML. Event handlers are attached here, never inline - the server's
 * Content-Security-Policy forbids inline script.
 */

const RESULTS_URL = '/data/weva-comparison.json';
const SVG_NS = 'http://www.w3.org/2000/svg';
const number = new Intl.NumberFormat('en-US');

/**
 * @param {string} tag
 * @param {Record<string, string>} [attrs]
 * @param {string} [text]
 * @returns {HTMLElement}
 */
function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
    if (text !== undefined) node.textContent = text;
    return node;
}

/**
 * @param {string} tag
 * @param {Record<string, string|number>} [attrs]
 * @returns {SVGElement}
 */
function svgEl(tag, attrs = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
    return node;
}

/** @returns {string} Milliseconds as m:ss. */
function clockText(ms) {
    const seconds = Math.floor(ms / 1000);
    return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

// =====================================================================
// RESULTS
// =====================================================================

/**
 * One table cell's text, and the value that ranks it - lower is better.
 * What counts as "better" depends on what the scenario measures: attack
 * requests that got through, legitimate users denied (then requests
 * refused), or - for the lockout scenario - whether the real owner got in.
 *
 * @param {object} scenario
 * @param {{attack: object|null, legit: object|null}} result
 * @returns {{value: number, main: string, sub: string}}
 */
function describeResult(scenario, result) {
    const { attack, legit } = result;
    if (scenario.measures === 'attack') {
        const noun = scenario.key === 'stolen-token' ? 'deletions ran' : 'guesses got through';
        return {
            value: attack.reached,
            main: `${number.format(attack.reached)} of ${number.format(attack.sent)} ${noun}`,
            sub: attack.firstRefusedAttempt ? `first stopped at attempt ${attack.firstRefusedAttempt}` : 'never stopped'
        };
    }
    if (scenario.measures === 'both') {
        return {
            value: legit.usersDenied * 1e6 + attack.reached,
            main: legit.usersDenied ? 'Real student locked out' : 'Real student signed in',
            sub: `${attack.reached} of ${attack.sent} attacker guesses checked`
        };
    }
    if (legit.users === 1) {
        return {
            value: legit.usersDenied * 1e6 + legit.refused,
            main: `${number.format(legit.refused)} ${legit.refused === 1 ? 'request' : 'requests'} refused`,
            sub: legit.usersDenied ? 'gave up before finishing' : (legit.worstDelaySeconds > 0 ? `finished, ${Math.round(legit.worstDelaySeconds)} s late` : 'finished without delay')
        };
    }
    return {
        value: legit.usersDenied * 1e6 + legit.refused,
        main: `${number.format(legit.usersDenied)} of ${number.format(legit.users)} denied`,
        sub: `${number.format(legit.refused)} requests refused`
    };
}

/**
 * Marks the best and worst cell of a row (lowest and highest value), unless
 * every cell ties. Labeled in text as well as tint, so the marking never
 * depends on color alone.
 *
 * @param {HTMLTableCellElement[]} cells
 * @param {number[]} values
 * @returns {void}
 */
function markBestAndWorst(cells, values) {
    const min = Math.min(...values);
    const max = Math.max(...values);
    if (min === max) return;
    cells.forEach((cell, i) => {
        const flag = values[i] === min ? 'Best' : values[i] === max ? 'Worst' : null;
        if (!flag) return;
        cell.classList.add(flag === 'Best' ? 'is-best' : 'is-worst');
        cell.querySelector('.cell-main').appendChild(el('span', { class: 'cell-flag' }, flag));
    });
}

/** @returns {void} */
function renderProvenance(report) {
    const env = report.environment;
    const t = env.weva.thresholds;
    document.getElementById('provenance').textContent =
        `Results generated ${new Date(report.generatedAt).toLocaleString()} by ${report.command} · seed ${env.seed} · ` +
        `express-rate-limit ${env.expressRateLimit} · Node ${env.node} · WEVA thresholds ${t.suspicious}/${t.critical}/${t.block} ` +
        `(admins +${env.weva.adminTolerance}), ${env.weva.windowMs / 1000} s window, ${env.weva.blockMs / 1000} s block.`;
}

/** @returns {void} */
function renderAlgorithmList(report) {
    const list = document.getElementById('algorithmList');
    list.replaceChildren();
    for (const algorithm of report.algorithms) {
        const point = report.tradeoff.points.find(p => p.algorithm === algorithm.id);
        const cost = report.decisionCost[algorithm.id];
        const ours = algorithm.id === 'weva';
        const item = el('li', ours ? { class: 'is-ours' } : {});

        const name = el('div', { class: 'algorithm-name' });
        const swatch = el('span', { class: 'swatch', 'aria-hidden': 'true' });
        swatch.style.background = ours ? 'var(--mark-weva)' : 'var(--mark-baseline)';
        name.append(swatch, document.createTextNode(algorithm.label));
        if (ours) name.appendChild(el('span', { class: 'ours-tag' }, 'Ours'));

        const totals = el('div', { class: 'algorithm-totals' });
        for (const [label, value] of [
            ['Attack through', point.attackThrough],
            ['Legit refused', point.legitRefused],
            ['Users denied', point.usersDenied]
        ]) {
            const part = el('span', {}, `${label} `);
            part.appendChild(el('strong', {}, number.format(value)));
            totals.appendChild(part);
        }
        const costPart = el('span', {}, 'Decision ');
        costPart.appendChild(el('strong', {}, `${cost.medianMicros} µs`));
        totals.appendChild(costPart);

        item.append(name, el('p', { class: 'algorithm-summary' }, algorithm.summary), totals);
        list.appendChild(item);
    }
}

/** @returns {void} */
function renderMatrix(report, onReplay) {
    const table = document.getElementById('resultsTable');
    const headRow = table.tHead.rows[0];
    headRow.replaceChildren(el('th', { scope: 'col' }, 'Scenario'));
    for (const algorithm of report.algorithms) headRow.appendChild(el('th', { scope: 'col' }, algorithm.label));

    const body = table.tBodies[0];
    body.replaceChildren();
    for (const scenario of report.scenarios) {
        const row = el('tr');
        const head = el('th', { scope: 'row' }, `${scenario.id}. ${scenario.title}`);
        head.appendChild(el('span', { class: 'scenario-tests' }, scenario.tests));
        const replay = el('button', { type: 'button', class: 'replay-link' }, 'Replay ▸');
        replay.addEventListener('click', () => onReplay(scenario.key));
        head.appendChild(replay);
        row.appendChild(head);

        const cells = [];
        const values = [];
        for (const algorithm of report.algorithms) {
            const { value, main, sub } = describeResult(scenario, scenario.results[algorithm.id]);
            const cell = el('td');
            cell.append(el('span', { class: 'cell-main' }, main), el('span', { class: 'cell-sub' }, sub));
            row.appendChild(cell);
            cells.push(cell);
            values.push(value);
        }
        markBestAndWorst(cells, values);
        body.appendChild(row);
    }
}

// ---------------------------------------------------------------------
// Trade-off chart: one point per algorithm, both axes symmetric-log
// (log10(1 + v)), since the totals run from 0 to the hundreds. WEVA is the
// accent; the baselines share one neutral gray, and every point is
// labeled directly, so identity never rests on telling hues apart.
// ---------------------------------------------------------------------
const CHART = { width: 560, height: 360, left: 62, right: 24, top: 16, bottom: 56 };
const symlog = (v) => Math.log10(1 + Math.max(0, v));

/** @returns {void} */
function renderTradeoff(report) {
    const box = document.getElementById('tradeoffChart');
    const tooltip = document.getElementById('tradeoffTooltip');
    const figure = box.parentElement;
    const points = report.tradeoff.points;
    const labelOf = (id) => report.algorithms.find(a => a.id === id).label;

    const largest = Math.max(1, ...points.flatMap(p => [p.attackThrough, p.legitRefused]));
    const top = 10 ** Math.ceil(Math.log10(largest + 1));
    const ticks = [0];
    for (let t = 1; t <= top; t *= 10) ticks.push(t);

    const plotW = CHART.width - CHART.left - CHART.right;
    const plotH = CHART.height - CHART.top - CHART.bottom;
    const sx = (v) => CHART.left + (symlog(v) / symlog(top)) * plotW;
    const sy = (v) => CHART.top + plotH - (symlog(v) / symlog(top)) * plotH;

    const summary = points.map(p => `${labelOf(p.algorithm)}: ${p.attackThrough} attack requests through, ${p.legitRefused} legitimate requests refused`).join('; ');
    const chart = svgEl('svg', { viewBox: `0 0 ${CHART.width} ${CHART.height}`, role: 'img', 'aria-label': `Trade-off chart. ${summary}.` });

    for (const t of ticks) {
        chart.appendChild(svgEl('line', { class: 'viz-grid', x1: sx(t), x2: sx(t), y1: CHART.top, y2: CHART.top + plotH }));
        chart.appendChild(svgEl('line', { class: 'viz-grid', x1: CHART.left, x2: CHART.left + plotW, y1: sy(t), y2: sy(t) }));
        const xLabel = svgEl('text', { class: 'viz-tick', x: sx(t), y: CHART.top + plotH + 18, 'text-anchor': 'middle' });
        xLabel.textContent = number.format(t);
        const yLabel = svgEl('text', { class: 'viz-tick', x: CHART.left - 10, y: sy(t) + 4, 'text-anchor': 'end' });
        yLabel.textContent = number.format(t);
        chart.append(xLabel, yLabel);
    }
    chart.appendChild(svgEl('line', { class: 'viz-axis', x1: CHART.left, x2: CHART.left + plotW, y1: CHART.top + plotH, y2: CHART.top + plotH }));
    chart.appendChild(svgEl('line', { class: 'viz-axis', x1: CHART.left, x2: CHART.left, y1: CHART.top, y2: CHART.top + plotH }));

    const xTitle = svgEl('text', { class: 'viz-title', x: CHART.left + plotW / 2, y: CHART.height - 10, 'text-anchor': 'middle' });
    xTitle.textContent = 'Legitimate requests refused (log scale)';
    const yTitle = svgEl('text', { class: 'viz-title', x: 14, y: CHART.top + plotH / 2, 'text-anchor': 'middle', transform: `rotate(-90 14 ${CHART.top + plotH / 2})` });
    yTitle.textContent = 'Attack requests that got through';
    const better = svgEl('text', { class: 'viz-better', x: CHART.left + 8, y: CHART.top + plotH - 8 });
    better.textContent = '↙ better on both';
    chart.append(xTitle, yTitle, better);

    const showTip = (point, x, y) => {
        tooltip.replaceChildren();
        tooltip.appendChild(el('div', { class: 'tip-title' }, labelOf(point.algorithm)));
        for (const [label, value] of [['Attack requests through', point.attackThrough], ['Legitimate requests refused', point.legitRefused], ['Users denied', point.usersDenied]]) {
            const row = el('div', { class: 'tip-row' });
            row.append(el('span', {}, label), el('strong', {}, number.format(value)));
            tooltip.appendChild(row);
        }
        const parts = [...point.breakdown.attack, ...point.breakdown.legit].map(b => `S${b.scenario}: ${b.value}`).join(' · ');
        tooltip.appendChild(el('div', { class: 'tip-sub' }, `By scenario - ${parts}`));
        tooltip.hidden = false;
        const scale = box.getBoundingClientRect().width / CHART.width;
        const left = Math.min(x * scale + 16, figure.clientWidth - tooltip.offsetWidth - 4);
        tooltip.style.left = `${Math.max(0, left)}px`;
        tooltip.style.top = `${Math.max(0, y * scale - tooltip.offsetHeight - 10)}px`;
    };
    const hideTip = () => { tooltip.hidden = true; };

    // Baselines first, so WEVA's point is drawn on top of any overlap.
    const ordered = [...points].sort((a, b) => (a.algorithm === 'weva') - (b.algorithm === 'weva'));
    for (const point of ordered) {
        const x = sx(point.legitRefused);
        const y = sy(point.attackThrough);
        const ours = point.algorithm === 'weva';
        const group = svgEl('g');
        group.appendChild(svgEl('circle', { class: `viz-point ${ours ? 'viz-point--weva' : 'viz-point--baseline'}`, cx: x, cy: y, r: ours ? 7 : 6 }));

        const toLeft = x > CHART.left + plotW - 170;
        const label = svgEl('text', { class: 'viz-label', x: toLeft ? x - 12 : x + 12, y: y - 2, 'text-anchor': toLeft ? 'end' : 'start' });
        label.textContent = labelOf(point.algorithm);
        const sub = svgEl('text', { class: 'viz-label-sub', x: toLeft ? x - 12 : x + 12, y: y + 13, 'text-anchor': toLeft ? 'end' : 'start' });
        sub.textContent = `${number.format(point.attackThrough)} through · ${number.format(point.legitRefused)} refused`;
        group.append(label, sub);

        // The hit target is far larger than the dot, and focusable, so the
        // same details are there by keyboard as by mouse.
        const hit = svgEl('circle', {
            class: 'viz-hit', cx: x, cy: y, r: 16, tabindex: 0, role: 'button',
            'aria-label': `${labelOf(point.algorithm)}: ${point.attackThrough} attack requests through, ${point.legitRefused} legitimate requests refused`
        });
        hit.addEventListener('pointerenter', () => showTip(point, x, y));
        hit.addEventListener('focus', () => showTip(point, x, y));
        hit.addEventListener('pointerleave', hideTip);
        hit.addEventListener('blur', hideTip);
        group.appendChild(hit);
        chart.appendChild(group);
    }

    box.replaceChildren(chart);
    const def = report.tradeoff.definition;
    document.getElementById('tradeoffCaption').textContent = `${def.attackThrough} ${def.legitRefused} Both axes are logarithmic.`;
}

// =====================================================================
// SCENARIO REPLAY
// =====================================================================

/** Wall-clock length of every replay, whatever the scenario's simulated duration. */
const REPLAY_WALL_MS = 14000;
/** Share of each lane's width given to its row labels. */
const GUTTER = 110;
const LANE_WIDTH = 1000;
const ROW_HEIGHT = 26;
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/** Outcome codes in the results file's replay lanes (bench/run-comparison.js). */
const OUTCOME = { ATTACK_THROUGH: 0, ATTACK_STOPPED: 1, LEGIT_SERVED: 2, LEGIT_REFUSED: 3 };

const replay = { report: null, scenario: null, lanes: [], simTime: 0, duration: 1, playing: false, raf: null, lastFrame: null };

/** @returns {string[]} The rows a scenario's lanes need. */
function rowsFor(scenario) {
    if (scenario.measures === 'both') return ['attack', 'legit'];
    return [scenario.measures];
}

/** @returns {object} One algorithm's lane: its DOM, its events, and its live counters. */
function buildLane(algorithm, scenario) {
    const rows = rowsFor(scenario);
    const height = rows.length * ROW_HEIGHT + 6;
    const lane = el('div', { class: 'lane' });
    const head = el('div', { class: 'lane-head' });
    const name = el('div', { class: 'lane-name' }, algorithm.label);
    if (algorithm.id === 'weva') name.appendChild(el('span', { class: 'ours-tag' }, 'Ours'));
    const counts = el('div', { class: 'lane-counts' });
    head.append(name, counts);

    const chart = svgEl('svg', { viewBox: `0 0 ${LANE_WIDTH} ${height}`, 'aria-hidden': 'true' });
    rows.forEach((row, i) => {
        const y = i * ROW_HEIGHT + 3;
        chart.appendChild(svgEl('rect', { class: 'lane-track', x: GUTTER, y, width: LANE_WIDTH - GUTTER, height: ROW_HEIGHT - 4, rx: 6 }));
        const label = svgEl('text', { class: 'lane-row-label', x: GUTTER - 10, y: y + ROW_HEIGHT / 2 + 2, 'text-anchor': 'end' });
        label.textContent = row === 'attack' ? (scenario.measures === 'both' ? 'Attacker' : 'Attack') : (scenario.measures === 'both' ? 'Real student' : 'Legitimate');
        chart.appendChild(label);
    });
    const okLayer = svgEl('g');
    const failLayer = svgEl('g');
    const cursor = svgEl('line', { class: 'lane-cursor', x1: GUTTER, x2: GUTTER, y1: 0, y2: height });
    chart.append(okLayer, failLayer, cursor);

    const { main, sub } = describeResult(scenario, scenario.results[algorithm.id]);
    const final = el('p', { class: 'lane-final' }, `${main} - ${sub}.`);
    final.hidden = true;
    lane.append(head, chart, final);

    return {
        element: lane, counts, okLayer, failLayer, cursor, final, rows,
        events: scenario.replay.lanes[algorithm.id],
        next: 0,
        stacked: new Map(),
        tally: { through: 0, stopped: 0, served: 0, refused: 0 }
    };
}

/** @returns {void} */
function renderCounts(lane) {
    const { tally, rows, counts } = lane;
    counts.replaceChildren();
    const part = (label, value, failure) => {
        const span = el('span', {}, `${label} `);
        span.appendChild(el('span', failure && value > 0 ? { class: 'fail' } : {}, number.format(value)));
        return span;
    };
    const pieces = [];
    if (rows.includes('attack')) pieces.push(part('Attack through', tally.through, true), part('stopped', tally.stopped, false));
    if (rows.includes('legit')) pieces.push(part('Legit refused', tally.refused, true), part('served', tally.served, false));
    pieces.forEach((piece, i) => {
        if (i > 0) counts.appendChild(document.createTextNode(' · '));
        counts.appendChild(piece);
    });
}

/** Draws every event up to `simTime` on every lane, and moves the cursor. */
function advanceTo(simTime) {
    const x = GUTTER + (simTime / replay.duration) * (LANE_WIDTH - GUTTER);
    for (const lane of replay.lanes) {
        while (lane.next < lane.events.length && lane.events[lane.next][0] * 100 <= simTime) {
            const [tenths, code] = lane.events[lane.next++];
            const isAttack = code === OUTCOME.ATTACK_THROUGH || code === OUTCOME.ATTACK_STOPPED;
            const failure = code === OUTCOME.ATTACK_THROUGH || code === OUTCOME.LEGIT_REFUSED;
            if (code === OUTCOME.ATTACK_THROUGH) lane.tally.through++;
            else if (code === OUTCOME.ATTACK_STOPPED) lane.tally.stopped++;
            else if (code === OUTCOME.LEGIT_SERVED) lane.tally.served++;
            else lane.tally.refused++;

            const rowIndex = lane.rows.indexOf(isAttack ? 'attack' : 'legit');
            // Requests at the same instant fan out vertically instead of
            // hiding behind one another.
            const key = `${rowIndex}:${tenths}`;
            const k = lane.stacked.get(key) ?? 0;
            lane.stacked.set(key, k + 1);
            const offset = [0, -5, 5, -9, 9][k % 5];
            const cx = GUTTER + ((tenths * 100) / replay.duration) * (LANE_WIDTH - GUTTER);
            const cy = rowIndex * ROW_HEIGHT + 3 + (ROW_HEIGHT - 4) / 2 + offset;
            (failure ? lane.failLayer : lane.okLayer).appendChild(svgEl('circle', {
                class: failure ? 'mark-fail' : 'mark-ok', cx, cy, r: failure ? 4 : 2.2
            }));
        }
        lane.cursor.setAttribute('x1', x);
        lane.cursor.setAttribute('x2', x);
        renderCounts(lane);
    }
    document.getElementById('replayClock').textContent = clockText(simTime);
}

/** @returns {void} */
function finishReplay() {
    replay.playing = false;
    advanceTo(replay.duration);
    replay.lanes.forEach(lane => { lane.final.hidden = false; });
    document.getElementById('replayPlay').textContent = 'Play again';
}

/** @returns {void} */
function frame(timestamp) {
    if (!replay.playing) return;
    const dt = replay.lastFrame === null ? 0 : timestamp - replay.lastFrame;
    replay.lastFrame = timestamp;
    replay.simTime = Math.min(replay.duration, replay.simTime + (dt * replay.duration) / REPLAY_WALL_MS);
    advanceTo(replay.simTime);
    if (replay.simTime >= replay.duration) {
        finishReplay();
        return;
    }
    replay.raf = requestAnimationFrame(frame);
}

/** @returns {void} */
function pauseReplay() {
    replay.playing = false;
    cancelAnimationFrame(replay.raf);
    document.getElementById('replayPlay').textContent = 'Play';
}

/** @returns {void} */
function playReplay() {
    if (replay.simTime >= replay.duration) loadScenario(replay.scenario.key);
    if (reducedMotion) {
        finishReplay();
        return;
    }
    replay.playing = true;
    replay.lastFrame = null;
    document.getElementById('replayPlay').textContent = 'Pause';
    replay.raf = requestAnimationFrame(frame);
}

/** Builds the replay for one scenario, at time zero. */
function loadScenario(key) {
    pauseReplay();
    const scenario = replay.report.scenarios.find(s => s.key === key);
    replay.scenario = scenario;
    // A little past the last request, so a request at the very end is not
    // drawn half off the edge of the lane.
    replay.duration = Math.max(1000, Math.ceil(scenario.replay.durationMs * 1.04));
    replay.simTime = 0;
    document.getElementById('replayScenario').value = key;
    document.getElementById('replayDescription').textContent = `${scenario.id}. ${scenario.title} - ${scenario.description}`;
    document.getElementById('replayTests').textContent = `Tests: ${scenario.tests}`;
    document.getElementById('replayDuration').textContent = clockText(replay.duration);

    replay.lanes = replay.report.algorithms.map(algorithm => buildLane(algorithm, scenario));
    document.getElementById('replayLanes').replaceChildren(...replay.lanes.map(lane => lane.element));

    const axis = document.getElementById('replayAxis');
    const ticks = el('div');
    ticks.style.cssText = `display:flex;justify-content:space-between;margin-left:${(GUTTER / LANE_WIDTH) * 100}%;width:${100 - (GUTTER / LANE_WIDTH) * 100}%`;
    for (const share of [0, 0.25, 0.5, 0.75, 1]) ticks.appendChild(el('span', {}, clockText(replay.duration * share)));
    axis.replaceChildren(ticks);

    renderSweep(scenario);
    // Nothing is drawn until Play, not even the requests sent at 0:00.
    replay.lanes.forEach(renderCounts);
    document.getElementById('replayClock').textContent = clockText(0);
    document.getElementById('replayPlay').textContent = 'Play';
}

/** The campus-size sweep under scenario 6's replay: where each algorithm starts denying students. */
function renderSweep(scenario) {
    const container = document.getElementById('replaySweep');
    if (!scenario.sweep) {
        container.hidden = true;
        container.replaceChildren();
        return;
    }
    const algorithms = replay.report.algorithms;
    const table = el('table', { class: 'matrix' });
    const head = el('tr');
    head.appendChild(el('th', { scope: 'col' }, 'Students behind the IP'));
    algorithms.forEach(a => head.appendChild(el('th', { scope: 'col' }, a.label)));
    table.appendChild(el('thead')).appendChild(head);
    const body = table.appendChild(el('tbody'));
    for (const row of scenario.sweep) {
        const tr = el('tr');
        tr.appendChild(el('th', { scope: 'row' }, number.format(row.students)));
        const cells = [];
        const values = [];
        for (const algorithm of algorithms) {
            const legit = row.results[algorithm.id];
            const cell = el('td');
            cell.append(
                el('span', { class: 'cell-main' }, `${number.format(legit.usersDenied)} denied`),
                el('span', { class: 'cell-sub' }, `${number.format(legit.refused)} refused`)
            );
            tr.appendChild(cell);
            cells.push(cell);
            values.push(legit.usersDenied * 1e6 + legit.refused);
        }
        markBestAndWorst(cells, values);
        body.appendChild(tr);
    }
    container.replaceChildren(
        el('h3', {}, 'Campus size sweep'),
        el('p', {}, `The same ${scenario.params.arrivalWindowMs / 60000}-minute rush and ${Math.round(scenario.params.typoRate * 100)}% typo rate, with more and more students behind the one campus IP. The first row where an algorithm denies students is its breaking point.`),
        el('div', { class: 'table-wrap' }, undefined)
    );
    container.lastChild.appendChild(table);
    container.hidden = false;
}

/** @returns {void} */
function initReplay(report) {
    replay.report = report;
    const select = document.getElementById('replayScenario');
    select.replaceChildren(...report.scenarios.map(s => el('option', { value: s.key }, `${s.id}. ${s.title}`)));
    select.addEventListener('change', () => loadScenario(select.value));
    document.getElementById('replayPlay').addEventListener('click', () => (replay.playing ? pauseReplay() : playReplay()));
    document.getElementById('replayRestart').addEventListener('click', () => {
        loadScenario(replay.scenario.key);
        playReplay();
    });
    loadScenario(report.scenarios[0].key);
}

/** @returns {Promise<void>} */
async function initResults() {
    let report = null;
    try {
        const response = await fetch(RESULTS_URL, { cache: 'no-store' });
        if (response.ok) report = await response.json();
    } catch (err) {
        console.error('[compare] Could not load comparison results:', err);
    }

    if (!report) {
        const provenance = document.getElementById('provenance');
        provenance.classList.add('is-missing');
        provenance.textContent = 'No comparison results yet. Run `npm run bench:compare` on the server\'s machine to generate public/data/weva-comparison.json, then reload.';
        document.getElementById('replayPlay').disabled = true;
        document.getElementById('replayRestart').disabled = true;
        return;
    }

    renderProvenance(report);
    renderTradeoff(report);
    renderAlgorithmList(report);
    initReplay(report);
    renderMatrix(report, (key) => {
        loadScenario(key);
        document.getElementById('replay').scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
        playReplay();
    });
}

// =====================================================================
// TRY IT YOURSELF
// =====================================================================

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

/**
 * Disables `button` until `until`, counting down on its label, then runs
 * `onLift`. Shared by all three cards.
 *
 * @param {HTMLButtonElement} button
 * @param {number} until - Epoch milliseconds when the refusal lifts.
 * @param {() => void} onLift
 * @returns {void}
 */
function holdUntil(button, until, onLift) {
    const idleLabel = button.textContent;
    button.disabled = true;
    const tick = () => {
        const left = Math.ceil((until - Date.now()) / 1000);
        if (left > 0) {
            button.textContent = `Refused: ${clockText(left * 1000)} left`;
            return;
        }
        clearInterval(timer);
        button.disabled = false;
        button.textContent = idleLabel;
        onLift();
    };
    const timer = setInterval(tick, 250);
    tick();
}

// ---- Account lockout: 3 failures lock the account for 15 minutes ----
// Matches the lockout baseline in bench/algorithms.js.
const LOCKOUT_THRESHOLD = 3;
const LOCKOUT_MS = 15 * 60 * 1000;
let lockoutFailures = 0;

/** Simulates one failed login against the account lockout. */
function testLockout() {
    lockoutFailures++;
    const btn = document.getElementById('btn-trad');
    if (lockoutFailures >= LOCKOUT_THRESHOLD) {
        lockoutFailures = 0;
        setStatus('status-trad', 'LOCKED: account locked for 15 min', 'blocked');
        addLog('log-trad', 'Third failure: account locked. Its real owner is locked out too.');
        holdUntil(btn, Date.now() + LOCKOUT_MS, () => setStatus('status-trad', 'UNLOCKED', ''));
    } else {
        setStatus('status-trad', `FAILED: attempt ${lockoutFailures} of ${LOCKOUT_THRESHOLD}`, 'warning');
        addLog('log-trad', 'Invalid login attempt.');
    }
}

// ---- Fixed window (strict): 5 failures per IP per 15-minute window ----
// Matches express-rate-limit as configured in bench/algorithms.js: the
// window starts at the first counted request and resets 15 minutes later,
// whatever happens in between.
const WINDOW_MS = 15 * 60 * 1000;
const WINDOW_LIMIT = 5;
const fixedWindow = { hits: 0, resetAt: 0 };

/** Simulates one failed login against the strict fixed window. */
function testFixedWindow() {
    const now = Date.now();
    const btn = document.getElementById('btn-fw');
    if (now >= fixedWindow.resetAt) {
        fixedWindow.hits = 0;
        fixedWindow.resetAt = now + WINDOW_MS;
    }
    fixedWindow.hits++;
    if (fixedWindow.hits > WINDOW_LIMIT) {
        setStatus('status-fw', 'REFUSED: limit reached (HTTP 429)', 'blocked');
        addLog('log-fw', `Failure ${fixedWindow.hits} in this window: refused until the window resets.`);
        holdUntil(btn, fixedWindow.resetAt, () => setStatus('status-fw', 'WINDOW RESET', ''));
    } else {
        setStatus('status-fw', `FAILED: ${fixedWindow.hits} of ${WINDOW_LIMIT} this window`, 'warning');
        addLog('log-fw', `Invalid login attempt (${WINDOW_LIMIT - fixedWindow.hits} left in this window).`);
    }
}

// ---- WEVA (Weighted Endpoint & Velocity Algorithm) ----
// Every score below comes from computeScore() - the production function.
// Around it, this card reproduces what the server does for one device
// sending failed attempts to POST /api/login (weight 2x), using
// config/securityConfig.js's defaults:
//   - core/monitor.js: request rate across the last 30 s, and the count
//     of prior login attempts;
//   - core/profiler.js: the device's EMA baseline rate (alpha 0.1), learned
//     only from attempts WEVA let through (ALLOW or LOG);
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

    const decision = decide(result.score);

    device.requests.push(now);
    device.loginAttempts += 1;
    // A throttled or blocked attempt is never learned as normal.
    if (decision === 'ALLOW' || decision === 'LOG') {
        device.baselineRate = requestRate * WEVA_EMA_ALPHA + device.baselineRate * (1 - WEVA_EMA_ALPHA);
    }

    return { ...result, decision };
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
        holdUntil(btn, now + WEVA_BLOCK_MS, () => {
            setStatus('status-weva', 'BLOCK LIFTED (attempt history kept)', '');
            addLog('log-weva', 'Temporary block lifted. The next attempt is still scored with every earlier failure.');
        });
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

document.getElementById('btn-trad').addEventListener('click', testLockout);
document.getElementById('btn-fw').addEventListener('click', testFixedWindow);
document.getElementById('btn-weva').addEventListener('click', testWeva);

initResults();
