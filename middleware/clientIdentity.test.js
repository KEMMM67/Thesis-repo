import { describe, it, expect } from 'vitest';
import { readDeviceId, getClientIdentity, accountKey, parseAccountKey, normalizeAccount, readTargetAccount, readLoginPortal, normalizeIp } from './clientIdentity.js';

const withHeader = (value, ip = '203.0.113.20') => ({ headers: { 'x-device-id': value }, ip });

describe('readDeviceId', () => {
    it('accepts the browser fingerprint format and the load test\'s IDs', () => {
        expect(readDeviceId(withHeader('DEV-1a2b3c4d'))).toBe('DEV-1a2b3c4d');
        expect(readDeviceId(withHeader('k6-mueeocyw-bot-1'))).toBe('k6-mueeocyw-bot-1');
    });

    it('rejects anything shaped like an IP, so a header can never impersonate an address', () => {
        expect(readDeviceId(withHeader('203.0.113.7'))).toBeNull();
        expect(readDeviceId(withHeader('::1'))).toBeNull();
        expect(readDeviceId(withHeader('::ffff:203.0.113.7'))).toBeNull();
    });

    it('rejects oversized, whitespace, and log-forging values', () => {
        expect(readDeviceId(withHeader('a'.repeat(46)))).toBeNull();
        expect(readDeviceId(withHeader('bad id'))).toBeNull();
        expect(readDeviceId(withHeader('x\n[SECURITY] Decision: ALLOW'))).toBeNull();
        expect(readDeviceId(withHeader(''))).toBeNull();
        expect(readDeviceId({ headers: {} })).toBeNull();
    });
});

describe('getClientIdentity', () => {
    it('falls back to the IP as the device key when the header is missing or invalid', () => {
        expect(getClientIdentity(withHeader('203.0.113.7', '198.51.100.4'))).toEqual({
            ip: '198.51.100.4', deviceId: null, deviceKey: '198.51.100.4'
        });
    });

    it('normalizes IPv4-mapped IPv6 addresses the same way the IP whitelist does', () => {
        expect(getClientIdentity({ headers: {}, ip: '::ffff:127.0.0.1' }).ip).toBe('127.0.0.1');
    });
});

describe('account identities', () => {
    it('keys a signed-in account as user:<id>, short enough for ip_tracking.ip_address (45 chars)', () => {
        expect(accountKey(17)).toBe('user:17');
        expect(accountKey(2147483647).length).toBeLessThanOrEqual(45);
    });

    it('recognises only account keys - never a device ID or an IP - when parsing', () => {
        expect(parseAccountKey('user:17')).toBe(17);
        expect(parseAccountKey('DEV-1a2b3c4d')).toBeNull();
        expect(parseAccountKey('203.0.113.7')).toBeNull();
        expect(parseAccountKey('user:17x')).toBeNull();
    });

    it('can never collide with a device ID, which may not contain ":"', () => {
        expect(readDeviceId(withHeader(accountKey(17)))).toBeNull();
    });

    it('normalizes the target account of a login attempt so case and spacing do not split it', () => {
        expect(normalizeAccount(' Alice@X.edu.ph ')).toBe('alice@x.edu.ph');
        expect(readTargetAccount({ body: { email: 'Alice@X.edu.ph' } })).toBe('alice@x.edu.ph');
        expect(readTargetAccount({ body: { email: { not: '' } } })).toBe('');
        expect(readTargetAccount({})).toBe('');
    });
});

describe('readLoginPortal', () => {
    it('is the Admin Portal only when the request says so; anything else is the Student Portal', () => {
        expect(readLoginPortal({ body: { portal: 'admin' } })).toBe('admin');
        expect(readLoginPortal({ body: { portal: 'student' } })).toBe('student');
        expect(readLoginPortal({ body: {} })).toBe('student');
        expect(readLoginPortal({ body: { portal: ['admin'] } })).toBe('student');
        expect(readLoginPortal({})).toBe('student');
    });
});

describe('normalizeIp', () => {
    it('strips the IPv4-mapped IPv6 prefix and leaves everything else alone', () => {
        expect(normalizeIp('::ffff:10.0.0.5')).toBe('10.0.0.5');
        expect(normalizeIp('10.0.0.5')).toBe('10.0.0.5');
        expect(normalizeIp('::1')).toBe('::1');
        expect(normalizeIp(undefined)).toBeUndefined();
    });
});
