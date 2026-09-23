import { normalizeIp } from "./ipWhitelistMiddleware.js";

/**
 * @fileoverview The two identities WEVA can attach to a request, derived in
 * exactly one place so middleware/securityMiddleware.js (which scores and
 * blocks them) and controllers/authController.js (which clears them after a
 * successful login) can never disagree about which key a request belongs to.
 *
 *   - deviceId: the client-supplied `x-device-id` header - the browser
 *     fingerprint public/*.js sends ("DEV-" plus up to 8 hex digits). It
 *     tells apart many users behind one shared IP, but the client controls
 *     it completely.
 *   - ip: the server-observed address (req.ip), normalized the same way
 *     middleware/ipWhitelistMiddleware.js normalizes the addresses it
 *     blocks. Only as trustworthy as server.js's `trust proxy` setting:
 *     that must match the number of proxies in front of the app, or req.ip
 *     is a proxy's address rather than the client's.
 *
 * DEVICE_ID_PATTERN is what keeps the two from ever colliding. A device ID
 * may only contain letters, digits, "_" and "-", so it can never contain the
 * "." or ":" that every IPv4/IPv6 address has. Without that rule, a bot could
 * send `x-device-id: 203.0.113.7` and have its failures - and its block -
 * recorded against whoever really is at 203.0.113.7. The 45-character cap
 * matches ip_tracking.ip_address (VARCHAR(45)), where a blocked device ID is
 * persisted. Anything else (IP-shaped, too long, whitespace, control
 * characters that could forge lines in the security log) is treated as no
 * header at all, so the request is identified by its IP alone - the strict,
 * pre-existing behavior for clients that send no device ID.
 */
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_-]{1,45}$/;

/**
 * @param {import("express").Request} req
 * @returns {string|null} The x-device-id header if it is well-formed, otherwise null.
 */
export function readDeviceId(req) {
    const raw = req.headers["x-device-id"];
    return typeof raw === "string" && DEVICE_ID_PATTERN.test(raw) ? raw : null;
}

/**
 * @param {import("express").Request} req
 * @returns {{ip: string, deviceId: string|null, deviceKey: string}} `deviceKey`
 *          is the device ID when present, otherwise the IP - the key WEVA's
 *          per-device history (core/monitor.js, core/profiler.js) is stored under.
 */
export function getClientIdentity(req) {
    const ip = normalizeIp(req.ip) || "unknown";
    const deviceId = readDeviceId(req);
    return { ip, deviceId, deviceKey: deviceId || ip };
}
