/**
 * @fileoverview The last two handlers in server.js's chain: a JSON 404 for
 * unknown API routes, and a JSON error handler for everything that throws.
 *
 * Why they exist: without them, Express's built-in handler answers errors
 * with an HTML page, and unless NODE_ENV is "production" that page contains
 * the full stack trace - server file paths, library versions, line numbers.
 * Two requests anyone can send produced one (reproduced against this app's
 * Express 5): a POST with malformed JSON (`{"email":`), and a POST /api/login
 * with no JSON body at all. These handlers never put `err.stack` or
 * `err.message` in a response, whatever NODE_ENV is; the detail goes to the
 * server log instead.
 */

/**
 * Fixed client messages for the errors express.json() raises, keyed by the
 * `type` body-parser sets on them - so a client learns what was wrong with
 * its request, but never the parser's own wording.
 */
const BODY_ERROR_MESSAGES = {
    'entity.parse.failed': 'The request body is not valid JSON.',
    'entity.too.large': 'The request body is too large.',
    'encoding.unsupported': 'The request body encoding is not supported.',
    'charset.unsupported': 'The request body charset is not supported.'
};

/**
 * Answers an API path no route matched with a JSON 404, in the same
 * { success, message } shape as every other API response - instead of
 * Express's HTML "Cannot GET ..." page. Mounted on "/api" only; pages and
 * static files keep Express's default 404.
 *
 * @type {import("express").RequestHandler}
 */
export function apiNotFound(req, res) {
    res.status(404).json({ success: false, message: 'Not found.' });
}

/**
 * Turns any error thrown or passed to next() into a JSON response.
 *
 *   - A client error (4xx, e.g. malformed JSON) keeps its status, with a
 *     fixed message.
 *   - Anything else is a 500 "Internal Server Error", and the full error is
 *     logged server-side, where the stack trace belongs.
 *
 * If a response has already started (e.g. a streaming export), the
 * connection is handed back to Express to close; a JSON body can no longer
 * be sent.
 *
 * @type {import("express").ErrorRequestHandler}
 */
export function jsonErrorHandler(err, req, res, next) {
    if (res.headersSent) return next(err);

    const status = Number.isInteger(err?.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
    if (status >= 500) {
        console.error(`[ERROR] ${req.method} ${req.originalUrl}:`, err);
    }

    const message = status >= 500
        ? 'Internal Server Error'
        : BODY_ERROR_MESSAGES[err?.type] ?? 'Bad request.';
    res.status(status).json({ success: false, message });
}
