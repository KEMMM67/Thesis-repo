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
 *      device remembers every attempt until its next successful login. An
 *      IP is shared - a campus NAT puts hundreds of students behind one
 *      address - so an IP history that never forgot would, after a single
 *      attack, keep refusing the whole campus for as long as anyone there
 *      kept trying to log in, since every new attempt would keep it alive.
 *      With a 30 s memory the address recovers on its own once the attack
 *      stops, while a bot that keeps going keeps its own window full and
 *      stays blocked.
 *
 *   2. It has no velocity term: the scorer is handed requestRate 0, so only
 *      the velocity floor and the fail-rate factor apply. Velocity is judged
 *      per device, where an EMA baseline describes one client's habits; the
 *      combined request rate of everyone behind a NAT describes nobody, and
 *      would throttle a busy campus simply for being busy.
 *
 * Worked example - a bot on one IP sending a new device ID with every guess
 * at POST /api/login (weight 2). Every guess's device score is 0, so the IP
 * decides, with score = 2 x 2 x (1 + 0.5 x recent attempts) x 5:
 *
 *   attempt   recent attempts before it   IP score   verdict
 *   1         0                           0          ALLOW    - reaches the password check
 *   2-4       1-3                         30-50      LOG      - reach the password check
 *   5-7       4-6                         60-80      THROTTLE
 *   8         7                           90         BLOCK    - the IP is blocked for 60 s
 *
 * That is exactly the ladder a single device gets - rotating IDs buys the
 * attacker nothing.
 *
 * controllers/authController.js clears an IP's attempts on any successful
 * login from it, for the same NAT reason: one student mistyping a password
 * three times should not start the next student on that network three rungs
 * up the ladder. The residual risk, stated plainly: an attacker who owns a
 * valid account on the same network can log into it between guesses to
 * reset this counter - though their device history still accumulates unless
 * they also rotate device IDs.
 */
const store = new MemoryStateStore();

/**
 * Returns the IP's attempt timestamps from inside the window, dropping older
 * ones from the stored entry as a side effect so it never grows unbounded.
 *
 * @param {string} ip
 * @param {number} now
 * @returns {number[]}
 */
function recentTimes(ip, now) {
    const entry = store.getOrCreate(ip, () => ({ times: [] }));
    entry.times = entry.times.filter(time => now - time < securityConfig.windowMs);
    return entry.times;
}

/**
 * @param {string} ip
 * @returns {number} Authentication attempts from this IP within the window.
 */
export function countRecentAttempts(ip) {
    return recentTimes(ip, Date.now()).length;
}

/**
 * @param {string} ip
 * @returns {void}
 */
export function recordAttempt(ip) {
    const now = Date.now();
    recentTimes(ip, now).push(now);
}

/**
 * Forgets an IP's recent attempts - called on a successful login from it.
 *
 * @param {string} ip
 * @returns {void}
 */
export function clearAttempts(ip) {
    if (store.has(ip)) store.set(ip, { times: [] });
}
