/**
 * @fileoverview The identities WEVA can attach to a request, derived in
 * exactly one place so middleware/securityMiddleware.js (which scores and
 * blocks them), controllers/authController.js (which settles them after a
 * successful login) and server.js (which lists and lifts blocks) can never
 * disagree about which key a request belongs to.
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
 *   - account key ("user:<id>"): the signed-in account, for authenticated
 *     requests. Unlike the other two it is server-verified - it comes from
 *     the JWT + session that middleware/authMiddleware.js checked - so it is
 *     the one identity a client cannot rotate. See accountKey() below.
 *   - target account: for a login or OTP attempt, the account the attempt
 *     is aimed at (the submitted email). Not a key WEVA scores or blocks on
 *     its own; it labels each attempt so a successful login settles only the
 *     attempts aimed at its own account. See normalizeAccount() below.
 *
 * DEVICE_ID_PATTERN is what keeps the stored keys from ever colliding. A
 * device ID may only contain letters, digits, "_" and "-", so it can never
 * contain the "." or ":" that every IPv4/IPv6 address has, nor the ":" of an
 * account key. Without that rule, a bot could send `x-device-id: 203.0.113.7`
 * and have its failures - and its block - recorded against whoever really is
 * at 203.0.113.7. The 45-character cap matches ip_tracking.ip_address
 * (VARCHAR(45)), where a blocked device ID is persisted. Anything else
 * (IP-shaped, too long, whitespace, control characters that could forge
 * lines in the security log) is treated as no header at all, so the request
 * is identified by its IP alone - the strict, pre-existing behavior for
 * clients that send no device ID.
 */
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_-]{1,45}$/;

/**
 * Prefix of an account key. No device ID can contain ":" (see
 * DEVICE_ID_PATTERN) and no IP address starts with "user", so an account key
 * can never be mistaken for either in the shared ip_tracking table.
 */
const ACCOUNT_KEY_PREFIX = "user:";
const ACCOUNT_KEY_PATTERN = /^user:(\d+)$/;

/**
 * Strips Node's IPv4-mapped IPv6 prefix, so "::ffff:127.0.0.1" and
 * "127.0.0.1" compare equal. Express's req.ip commonly reports a plain IPv4
 * loopback connection in the mapped form on a dual-stack listener, so
 * without this the campus whitelist's ALLOWED_ADMIN_IPS=127.0.0.1 could
 * fail to match the developer's own machine, and WEVA's IP layer would
 * count one client under two keys. Shared by both
 * (middleware/ipWhitelistMiddleware.js, getClientIdentity() below).
 *
 * @param {string} ip
 * @returns {string}
 */
export function normalizeIp(ip) {
    if (!ip) return ip;
    return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

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

/**
 * The key a signed-in account's own request history - and any block WEVA
 * places on the account as a whole - is stored under: "user:<id>". Built from
 * the numeric user id rather than the email so it always fits the 45
 * characters ip_tracking.ip_address allows ("user:" plus a Postgres integer
 * is at most 15), where a long university address would not.
 *
 * @param {number} userId
 * @returns {string} e.g. "user:17"
 */
export function accountKey(userId) {
    return `${ACCOUNT_KEY_PREFIX}${userId}`;
}

/**
 * @param {string} key - A stored WEVA identity key.
 * @returns {number|null} The user id if `key` is an account key, otherwise null (a device ID or IP).
 */
export function parseAccountKey(key) {
    const match = ACCOUNT_KEY_PATTERN.exec(key);
    return match ? Number(match[1]) : null;
}

/**
 * The form an account is recorded under when it is the *target* of a login
 * or OTP attempt: the email trimmed and lower-cased, so "Alice@X.edu" and
 * "alice@x.edu " count as one target. A missing or non-string email becomes
 * "", a target no successful login can ever settle.
 *
 * @param {*} email
 * @returns {string}
 */
export function normalizeAccount(email) {
    return typeof email === "string" ? email.trim().toLowerCase() : "";
}

/**
 * @param {import("express").Request} req - A POST /api/login or /api/verify-otp request.
 * @returns {string} The normalized account the attempt is aimed at ("" if none was submitted).
 */
export function readTargetAccount(req) {
    return normalizeAccount(req.body?.email);
}

/**
 * Which login page a POST /api/login comes from, as the page declares it in
 * the request body: "admin" from the Admin Portal (public/admin_login.js),
 * and "student" for anything else - including no value at all, which is
 * what the Student Portal (public/script.js) sends.
 *
 * Declaring a portal grants nothing; it narrows what can succeed.
 * controllers/authController.js#login accepts administrators only on the
 * Admin Portal and everyone else only on the Student Portal, failing the
 * wrong combination exactly like a wrong password; and
 * middleware/ipWhitelistMiddleware.js#createIpWhitelistForAdminLogin
 * refuses the Admin Portal from outside the campus network whatever email
 * is typed. Read in this one place so the two can never disagree.
 *
 * @param {import("express").Request} req
 * @returns {"admin"|"student"}
 */
export function readLoginPortal(req) {
    return req.body?.portal === "admin" ? "admin" : "student";
}
