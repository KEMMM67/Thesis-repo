/**
 * @fileoverview What WEVA reads from a request: who sent it (the
 * application-layer device ID and the IP) and which listed route it is.
 * Identity rules from the thesis build's middleware/clientIdentity.js.
 */

/**
 * A device ID may hold only letters, digits, "_" and "-", up to 45. It can
 * then never look like an IP (every IP has "." or ":"), so a client cannot
 * get its failures - or its block - recorded against someone else's address,
 * and cannot forge lines in a log. Anything else is ignored, and the request
 * is identified by its IP alone.
 */
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_-]{1,45}$/;

/**
 * @param {import('node:http').IncomingMessage & {ip?: string}} req
 * @param {string} header - Lower-case name of the header carrying the device ID.
 * @returns {{ip: string, deviceId: string|null, deviceKey: string}} `deviceKey`
 *          is the device ID, or the IP for a client that sends none.
 */
export function identifyClient(req, header) {
    // req.ip follows Express's "trust proxy" setting. Behind a proxy without
    // it, every client shares the proxy's address.
    const ip = normalizeIp(req.ip ?? req.socket?.remoteAddress) || 'unknown';
    const raw = req.headers[header];
    const deviceId = typeof raw === 'string' && DEVICE_ID_PATTERN.test(raw) ? raw : null;
    return { ip, deviceId, deviceKey: deviceId ?? ip };
}

/** "::ffff:127.0.0.1" and "127.0.0.1" are the same client. */
function normalizeIp(ip) {
    return typeof ip === 'string' && ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

/** Login targets compare trimmed and lower-cased; anything but a string becomes "". */
export function normalizeAccount(value) {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

/** The full request path wherever the middleware is mounted, without a trailing slash. */
export function requestPath(req) {
    const path = (req.baseUrl ?? '') + (req.path ?? req.url.split('?')[0]);
    return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

/**
 * Compiles route patterns such as "/api/students/:id" into a function that
 * returns the pattern a path belongs to, or null.
 *
 * Mounted with app.use(), WEVA runs before Express has matched a route, so it
 * matches paths itself - case-insensitively, as Express does by default.
 * Otherwise "/API/Login" would reach the login handler without counting as a
 * login attempt. Static patterns are tried first, so "/api/students/search"
 * wins over "/api/students/:id".
 *
 * @param {string[]} patterns
 * @returns {(path: string) => string|null}
 */
export function compileRoutes(patterns) {
    const routes = patterns
        .map(pattern => ({ pattern, regex: toRegex(pattern) }))
        .sort((a, b) => Number(a.pattern.includes('/:')) - Number(b.pattern.includes('/:')));
    return path => routes.find(route => route.regex.test(path))?.pattern ?? null;
}

function toRegex(pattern) {
    const trimmed = pattern.length > 1 ? pattern.replace(/\/$/, '') : pattern;
    const source = trimmed
        .split('/')
        .map(segment => (segment.startsWith(':') ? '[^/]+' : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
        .join('/');
    return new RegExp(`^${source}$`, 'i');
}
