import { securityConfig } from "../config/securityConfig.js";
import { MemoryStateStore } from "./stateStore.js";

/**
 * @fileoverview Recent authentication attempts per IP address - the
 * server-observed identity WEVA scores alongside the client-supplied device
 * ID on pre-authentication requests (see middleware/securityMiddleware.js).
 *
 * Why a second identity at all: core/monitor.js keys a device's failure
 * history on its x-device-id header, which the client controls. A bot that
 * sends a brand-new ID with every guess starts every guess with an empty
 * history - score 0, ALLOW - and is never escalated. Counting attempts per
 * IP too, and letting the higher of the two scores decide, closes that:
 * rotating IDs from one address still builds one IP history.
 *
 * It differs from the device history in two deliberate ways:
 *
 *   1. It only remembers the last `securityConfig.windowMs` (30 s), where a
 *      device remembers every attempt until a successful login settles it.
 *      An IP is shared - a campus NAT puts hundreds of students behind one
 *      address - so an IP history that never forgot would, after a single
 *      attack, keep refusing the whole campus for as long as anyone there
 *      kept trying to log in, since every new attempt would keep it alive.
 *      With a 30 s memory the address recovers on its own once the attack
 *      stops, while a bot that keeps going keeps refilling its own window
 *      and keeps being throttled.
 *
 *   2. It has no velocity term: the scorer is handed requestRate 0, so only
 *      the velocity floor and the fail-rate factor apply. Velocity is judged
 *      per device, where an EMA baseline describes one client's habits; the
 *      combined request rate of everyone behind a NAT describes nobody, and
 *      would throttle a busy campus simply for being busy.
 *
 *   3. It records only attempts that reach the password check
 *      (middleware/securityMiddleware.js decides, before calling
 *      recordAttempt()). A device records every attempt, refused or not;
 *      an IP must not, because on a shared address the refused attempts are
 *      mostly other people's. Recording them turned four coincidental typos
 *      on a campus NAT into a self-sustaining lockout of the whole campus -
 *      see the note at the end of the middleware's synchronous step.
 *
 * Worked example - a bot on one IP sending a new device ID with every guess
 * at POST /api/login (weight 2). Every guess's device score is 0, so the IP
 * decides, with score = 2 x 2 x (1 + 0.5 x failures in the window) x 5:
 *
 *   attempt   failures in the window   IP score   verdict
 *   1         0                        0          ALLOW    - reaches the password check
 *   2-4       1-3                      30-50      LOG      - reach the password check
 *   5 on      4                        60         THROTTLE - refused, and not recorded
 *
 * The window holds those 4 failures until each is 30 s old, so every
 * further guess is refused until the oldest ages out; then one more gets
 * through and is throttled again behind it. A bot rotating device IDs
 * therefore gets at most 4 password checks in any 30 s. That matches a
 * single device up to its THROTTLE, but the IP layer stops there: a device,
 * which records every attempt, climbs on to BLOCK at its 8th (core/scorer.js);
 * an IP never blocks.
 *
 * Each attempt is stored with the account it targeted, and a successful
 * login settles only that account's attempts (settleIpAttempts() below,
 * called from controllers/authController.js#completeLogin). This used to
 * clear the IP's whole window on any successful login, so that one student
 * mistyping a password three times would not start the next student on
 * that network three rungs up the ladder. But that also let an attacker
 * who owns any valid account reset the window by logging into it between
 * guesses - and since the device history was reset the same way, the
 * earlier note here that "their device history still accumulates" was
 * wrong: the combination was a complete bypass.
 *
 * Settling per account keeps the campus case and closes the bypass:
 *
 *   - Student A mistypes twice, then logs in. All three attempts target A,
 *     so A's success settles all three and the next student on the network
 *     starts at 0 - the same outcome as clearing the whole window.
 *   - A bot rotating device IDs guesses at account V while students log in
 *     around it. Each success settles only that student's own attempts;
 *     the bot's attempts at V stay in the window, so it is still throttled
 *     after 4 guesses, as above.
 *
 * The trade-offs that remain, stated plainly:
 *
 *   - Unsettled failures belong to the address. While a bot behind a shared
 *     IP keeps its window at 4, a legitimate attempt from that same IP is
 *     throttled too - until the bot's failures age out, at most 30 s after
 *     it stops. That is inherent to scoring a shared identifier;
 *     answering an IP-level verdict with a challenge such as a CAPTCHA,
 *     rather than a refusal, is future work.
 *   - A busy enough campus can still trip the IP layer on its own: with
 *     enough students behind one address, 4 typos can fall inside one 30 s
 *     window, and the next student is throttled (asked to retry in 15 s).
 *     In the comparison harness (bench/, scenario 6), 400 students signing
 *     in within 5 minutes lose 7 of themselves that way and 800 lose 325 -
 *     the measured breaking point.
 */
const store = new MemoryStateStore();

/**
 * Returns the IP's attempts from inside the window, dropping older ones
 * from the stored entry as a side effect so it never grows unbounded.
 *
 * @param {string} ip
 * @param {number} now
 * @returns {Array<{time: number, account: string}>}
 */
function recentAttempts(ip, now) {
    const entry = store.getOrCreate(ip, () => ({ attempts: [] }));
    entry.attempts = entry.attempts.filter(attempt => now - attempt.time < securityConfig.windowMs);
    return entry.attempts;
}

/**
 * @param {string} ip
 * @returns {number} Unsettled authentication attempts from this IP within the window, across all target accounts.
 */
export function countRecentAttempts(ip) {
    return recentAttempts(ip, Date.now()).length;
}

/**
 * Records an attempt from `ip` - only one that is going on to the password
 * check, never one WEVA refused (this file's @fileoverview, point 3).
 *
 * @param {string} ip
 * @param {string} [account=""] - Normalized account the attempt targets (middleware/clientIdentity.js#readTargetAccount).
 * @returns {void}
 */
export function recordAttempt(ip, account = '') {
    const now = Date.now();
    recentAttempts(ip, now).push({ time: now, account });
}

/**
 * Settles the attempts this IP made against `account` - called on a
 * successful login to that account from this IP. Attempts against other
 * accounts stay in the window (see this file's @fileoverview for why).
 *
 * @param {string} ip
 * @param {string} account - Normalized account that just logged in (middleware/clientIdentity.js#normalizeAccount).
 * @returns {void}
 */
export function settleIpAttempts(ip, account) {
    if (!store.has(ip)) return;
    const entry = store.getOrCreate(ip, () => ({ attempts: [] }));
    entry.attempts = entry.attempts.filter(attempt => attempt.account !== account);
}
