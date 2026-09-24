import { describe, it, expect, vi, afterEach } from 'vitest';
import { sendOtpEmail } from './emailService.js';

describe('sendOtpEmail', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
        vi.unstubAllEnvs();
    });

    it('delivers over Resend\'s HTTPS API when RESEND_API_KEY is set (no SMTP needed)', async () => {
        vi.stubEnv('RESEND_API_KEY', 're_test_key');
        const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: 'email-1' }), { status: 200 }));
        vi.stubGlobal('fetch', fetchMock);

        expect(await sendOtpEmail('admin@example.com', '004821', 5)).toBe(true);

        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toBe('https://api.resend.com/emails');
        expect(init.method).toBe('POST');
        expect(init.headers.Authorization).toBe('Bearer re_test_key');
        const body = JSON.parse(init.body);
        expect(body.to).toBe('admin@example.com');
        expect(body.from).toContain('onboarding@resend.dev');
        expect(body.html).toContain('004821');
    });

    it('reports failure (never throws) when Resend rejects the send', async () => {
        vi.stubEnv('RESEND_API_KEY', 're_test_key');
        vi.stubGlobal('fetch', vi.fn(async () => new Response('You can only send testing emails to your own email address', { status: 403 })));

        expect(await sendOtpEmail('someone-else@example.com', '004821', 5)).toBe(false);
    });

    it('reports failure when no delivery channel is configured', async () => {
        vi.stubEnv('RESEND_API_KEY', '');
        vi.stubEnv('SMTP_EMAIL', '');
        vi.stubEnv('SMTP_APP_PASSWORD', '');

        expect(await sendOtpEmail('admin@example.com', '004821', 5)).toBe(false);
    });
});
