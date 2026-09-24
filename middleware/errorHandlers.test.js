import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import express from 'express';
import { apiNotFound, jsonErrorHandler } from './errorHandlers.js';

/**
 * @fileoverview Runs the error handlers in a real Express 5 app on a random
 * local port, with NODE_ENV left unset - the setting under which Express's
 * own handler would print a stack trace.
 */

let server;
let base;

beforeAll(async () => {
    const app = express();
    app.use(express.json());
    // Same shape as the bug: destructuring a body that was never parsed.
    app.post('/api/destructure', async (req, res) => { const { email } = req.body; res.json({ email }); });
    app.get('/api/throws', () => { throw new Error('secret internal detail'); });
    app.use('/api', apiNotFound);
    app.use(jsonErrorHandler);
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
    vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => {
    server?.close();
    vi.restoreAllMocks();
});

/** Asserts the response is JSON and leaks no stack trace or internal detail. */
async function expectCleanJson(response, status, message) {
    const text = await response.text();
    expect(response.status).toBe(status);
    expect(response.headers.get('content-type')).toMatch(/application\/json/);
    expect(JSON.parse(text)).toEqual({ success: false, message });
    expect(text).not.toMatch(/\bat \S+ \(|node_modules|\.js:\d+|secret internal detail|Unexpected/);
}

describe('jsonErrorHandler / apiNotFound', () => {
    it('answers malformed JSON with a 400 JSON body, not an HTML stack trace', async () => {
        const response = await fetch(`${base}/api/destructure`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"email":' });
        await expectCleanJson(response, 400, 'The request body is not valid JSON.');
    });

    it('answers a crash with a generic 500 JSON body', async () => {
        await expectCleanJson(await fetch(`${base}/api/destructure`, { method: 'POST' }), 500, 'Internal Server Error');
        await expectCleanJson(await fetch(`${base}/api/throws`), 500, 'Internal Server Error');
    });

    it('answers an oversized body with 413', async () => {
        const response = await fetch(`${base}/api/destructure`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pad: 'x'.repeat(200_000) }) });
        await expectCleanJson(response, 413, 'The request body is too large.');
    });

    it('answers an unknown API route with a JSON 404', async () => {
        await expectCleanJson(await fetch(`${base}/api/no-such-route`), 404, 'Not found.');
    });
});
