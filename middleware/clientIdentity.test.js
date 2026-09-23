import { describe, it, expect } from 'vitest';
import { readDeviceId, getClientIdentity } from './clientIdentity.js';

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
