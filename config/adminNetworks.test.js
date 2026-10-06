import { describe, it, expect } from 'vitest';
import { parseAllowedAdminNetworks, isAllowedAdminIp, describeAdminWhitelist } from './adminNetworks.js';

function allows(raw, ip) {
    return isAllowedAdminIp(parseAllowedAdminNetworks(raw).blockList, ip);
}

describe('parseAllowedAdminNetworks', () => {
    it('matches single addresses exactly, as the whitelist always has', () => {
        expect(allows('127.0.0.1,::1', '127.0.0.1')).toBe(true);
        expect(allows('127.0.0.1,::1', '::1')).toBe(true);
        expect(allows('10.0.0.1', '10.0.0.10')).toBe(false);
    });

    it('admits every address inside an IPv4 range and nothing outside it', () => {
        const venue = '203.0.113.0/24';
        for (const ip of ['203.0.113.0', '203.0.113.17', '203.0.113.42', '203.0.113.255']) {
            expect(allows(venue, ip)).toBe(true);
        }
        for (const ip of ['203.0.112.255', '203.0.114.0', '198.51.100.17']) {
            expect(allows(venue, ip)).toBe(false);
        }
    });

    it('reads a range written with host bits set as the network it belongs to', () => {
        expect(allows('203.0.113.17/24', '203.0.113.200')).toBe(true);
    });

    it('admits addresses inside an IPv6 range', () => {
        expect(allows('2001:db8:abcd::/48', '2001:db8:abcd:12::7')).toBe(true);
        expect(allows('2001:db8:abcd::/48', '2001:db8:abce::7')).toBe(false);
    });

    it('treats an IPv4-mapped entry as the plain address it stands for', () => {
        expect(allows('::ffff:10.0.0.5', '10.0.0.5')).toBe(true);
    });

    it('ignores a malformed entry with a warning and keeps the valid ones', () => {
        const { blockList, entries, warnings } = parseAllowedAdminNetworks('10.0.0.5, localhost, 10.0.0.300, 203.0.113.0/33, 203.0.113.0/x, 1.2.3.4/24/8');
        expect(entries).toEqual(['10.0.0.5']);
        expect(warnings).toHaveLength(5);
        expect(warnings[0]).toMatch(/"localhost" ignored - not an IP address/);
        expect(warnings[2]).toMatch(/"\/33" is not a valid IPv4 prefix length/);
        expect(isAllowedAdminIp(blockList, '10.0.0.5')).toBe(true);
    });

    it('ignores a range broader than /16 or /32, so a typo cannot open the portal to the internet', () => {
        for (const [raw, probe] of [['0.0.0.0/0', '8.8.8.8'], ['203.0.113.0/2', '8.8.8.8'], ['10.0.0.0/15', '10.1.0.1'], ['2001:db8::/31', '2001:db8::1']]) {
            const { entries, warnings } = parseAllowedAdminNetworks(raw);
            expect(entries).toEqual([]);
            expect(warnings[0]).toMatch(/broader than the \/(16|32) limit/);
            expect(allows(raw, probe)).toBe(false);
        }
        expect(parseAllowedAdminNetworks('10.0.0.0/16').entries).toEqual(['10.0.0.0/16']);
    });

    it('never allows a missing or malformed request address', () => {
        for (const ip of [undefined, '', 'unknown']) {
            expect(allows('10.0.0.0/16', ip)).toBe(false);
        }
    });
});

describe('describeAdminWhitelist', () => {
    it('lists the entries it will enforce', () => {
        expect(describeAdminWhitelist({ ENABLE_IP_WHITELIST: 'true', ALLOWED_ADMIN_IPS: '127.0.0.1, 203.0.113.0/24' }))
            .toEqual({ summary: 'on - 127.0.0.1, 203.0.113.0/24', warnings: [] });
    });

    it('warns when enforcement is on but nothing valid is allowed', () => {
        const { summary, warnings } = describeAdminWhitelist({ ENABLE_IP_WHITELIST: 'true', ALLOWED_ADMIN_IPS: '203.0.113.0/2' });
        expect(summary).toBe('on - no valid entries');
        expect(warnings).toHaveLength(2);
        expect(warnings[1]).toMatch(/refused from every address/);
    });

    it('reports off without the lockout warning when enforcement is disabled', () => {
        expect(describeAdminWhitelist({})).toEqual({ summary: 'off - no valid entries', warnings: [] });
    });
});
