/**
 * @fileoverview Enforces a verdict, ported from the thesis build's
 * core/mitigation.js.
 *
 *   THROTTLE  429 Too Many Requests, Retry-After: 15. Answered at once:
 *             nothing is held open and nothing is stored.
 *   BLOCK     403 Forbidden, Retry-After: <seconds left>. The client is
 *             recorded in the block store for blockMs (60 s by default).
 *
 * Responses are written with Node's own res.setHeader() and res.end(), so
 * the middleware runs under Express 4, Express 5 or plain Connect.
 */

/**
 * The default block store: in memory, one process. Any object with the same
 * three async methods can replace it - Redis or a database table, so several
 * server instances share blocks. It is the IpTrackingStore port of the thesis
 * build's core/ports.js.
 */
export class MemoryBlockStore {
    #blockedUntil = new Map();
    #pruneAt = 1000;

    /** @returns {Promise<{isBlocked: boolean, blockedUntil: Date}|null>} */
    async findStatus(id) {
        const blockedUntil = this.#blockedUntil.get(id);
        return blockedUntil ? { isBlocked: true, blockedUntil } : null;
    }

    async block(id, blockedUntil) {
        this.#blockedUntil.set(id, blockedUntil);
        // A client that never comes back is never cleared by the middleware,
        // so expired blocks are dropped whenever the map doubles in size.
        if (this.#blockedUntil.size >= this.#pruneAt) {
            const now = Date.now();
            for (const [key, until] of this.#blockedUntil) {
                if (until.getTime() <= now) this.#blockedUntil.delete(key);
            }
            this.#pruneAt = Math.max(1000, this.#blockedUntil.size * 2);
        }
    }

    async clear(id) {
        this.#blockedUntil.delete(id);
    }
}

/**
 * @param {'ALLOW'|'LOG'|'THROTTLE'|'BLOCK'} decision
 * @param {import('node:http').ServerResponse} res
 * @param {string[]} identifiers - Every identity the request carries; the one whose score decided comes first.
 * @param {{blockStore: MemoryBlockStore, blockMs: number, throttleRetryAfterSeconds: number}} config
 * @returns {Promise<boolean>} true if a response was sent and the request must stop here.
 */
export async function applyMitigation(decision, res, identifiers, { blockStore, blockMs, throttleRetryAfterSeconds }) {
    const now = new Date();

    // An active block on ANY of the request's identities refuses it, whatever
    // this request scored. Otherwise a bot blocked under one device ID could
    // walk straight back in under a new one.
    const statuses = await Promise.all(identifiers.map(id => blockStore.findStatus(id)));
    const activeUntil = statuses
        .filter(status => status?.isBlocked && status.blockedUntil > now)
        .map(status => status.blockedUntil)
        .sort((a, b) => b - a)[0];
    if (activeUntil) {
        sendBlocked(res, activeUntil);
        return true;
    }

    if (decision === 'BLOCK') {
        // Only the identity that earned the verdict is blocked, so one
        // device's behavior never locks out everyone sharing its IP.
        const blockedUntil = new Date(now.getTime() + blockMs);
        await blockStore.block(identifiers[0], blockedUntil);
        sendBlocked(res, blockedUntil);
        return true;
    }

    if (decision === 'THROTTLE') {
        send(res, 429, throttleRetryAfterSeconds, {
            success: false,
            message: 'Too many attempts. Please wait.',
            retryAfter: throttleRetryAfterSeconds
        });
        return true;
    }

    // ALLOW or LOG: any block still on record has expired, so lift it.
    await Promise.all(identifiers.map((id, i) => (statuses[i]?.isBlocked ? blockStore.clear(id) : null)));
    return false;
}

/** 403 with the real time left on the block, rounded up so a client countdown never ends early. */
function sendBlocked(res, blockedUntil) {
    const seconds = Math.max(0, Math.ceil((blockedUntil.getTime() - Date.now()) / 1000));
    send(res, 403, seconds, {
        success: false,
        message: 'CRITICAL THREAT: Brute-force behavior detected. Access temporarily blocked.',
        retryAfterSeconds: seconds
    });
}

function send(res, statusCode, retryAfterSeconds, body) {
    res.statusCode = statusCode;
    res.setHeader('Retry-After', String(retryAfterSeconds));
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(body));
}
