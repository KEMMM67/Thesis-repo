/**
 * @fileoverview How many proxies in front of this server Express should
 * believe when it reads a client's address from X-Forwarded-For
 * (app.set('trust proxy', ...) in server.js).
 *
 * The number has to match the deployment exactly, in both directions:
 *
 *   - Too low, and req.ip is one of the host's own proxies, so every user
 *     shares one "IP": WEVA's IP layer (core/ipAttempts.js) and the
 *     campus-intranet whitelist (middleware/ipWhitelistMiddleware.js)
 *     collapse onto that single address.
 *   - Too high, and the client's own X-Forwarded-For header is believed,
 *     so anyone can pick their req.ip - past the whitelist, and a fresh
 *     "IP" per guess past the IP layer. This is what a hard-coded 3 did on
 *     any machine that is not Render: a direct connection sends no proxy
 *     header of its own, so a forged `X-Forwarded-For: 127.0.0.1` became
 *     the client's address (reproduced against this app's Express 5).
 *
 * On Render a request passes through Cloudflare, then Render's load
 * balancer, then an internal proxy, and arrives with a header shaped like:
 *
 *   X-Forwarded-For: 81.97.145.24, 172.71.195.123, 10.226.90.65
 *                    client        Cloudflare edge  Render internal
 *
 * with the socket itself coming from that internal proxy. Trusting 3 hops
 * walks back past the socket, 10.226.90.65 and 172.71.195.123 and stops on
 * the client. Both other values tried earlier failed visibly in the logs:
 * trusting 1 hop gave the Render-internal address (10.26.132.94) for
 * everyone; trusting private ranges stopped on the Cloudflare edge address,
 * which changes from request to request, so WEVA's IP layer never saw a
 * bot's attempts land on one "IP" and a rotating-device bot got 15
 * password checks before its first throttle instead of 4. It is also
 * spoof-proof there: Cloudflare and Render append to X-Forwarded-For rather
 * than resetting it, so anything a client writes sits to the LEFT of the
 * entry Cloudflare recorded and is never reached.
 *
 * So the value is chosen per deployment:
 *
 *   1. TRUST_PROXY_HOPS, when set - an explicit number of hops (0 = trust
 *      no proxy header at all). Set it on any host other than Render, or if
 *      Render ever adds or removes a hop.
 *   2. Otherwise 3 on Render, detected by the RENDER=true variable Render
 *      sets on every service - so the Render deployment needs no setting.
 *   3. Otherwise 0: a local or LAN server trusts no forwarded header, and
 *      req.ip is the real socket address.
 *
 * After a deploy, check that the [SECURITY] log's IP matches
 * https://api.ipify.org from the same browser.
 */

/** Proxy hops between a client and this app on Render - see this file's @fileoverview. */
const RENDER_PROXY_HOPS = 3;

/** More hops than any realistic deployment; a larger value is almost certainly a typo. */
const MAX_PROXY_HOPS = 10;

/**
 * @param {Record<string, string|undefined>} env - Usually process.env.
 * @returns {{hops: number, source: string}} Hops for app.set('trust proxy', ...) and a human-readable reason, for the startup log.
 * @throws {Error} If TRUST_PROXY_HOPS is set to something other than a whole number from 0 to 10 - a wrong value silently weakens the IP whitelist and WEVA's IP layer, so it fails loudly at startup instead.
 */
export function resolveTrustProxy(env) {
    const configured = (env.TRUST_PROXY_HOPS ?? '').trim();
    if (configured !== '') {
        const hops = Number(configured);
        if (!Number.isInteger(hops) || hops < 0 || hops > MAX_PROXY_HOPS) {
            throw new Error(`TRUST_PROXY_HOPS must be a whole number from 0 to ${MAX_PROXY_HOPS} (got "${configured}").`);
        }
        return { hops, source: 'TRUST_PROXY_HOPS' };
    }

    if ((env.RENDER ?? '').trim().toLowerCase() === 'true') {
        return { hops: RENDER_PROXY_HOPS, source: 'Render detected (RENDER=true)' };
    }

    return { hops: 0, source: 'no proxy configured - using the socket address' };
}
