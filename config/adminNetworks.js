import { BlockList, isIPv4, isIPv6 } from "node:net";
import { normalizeIp } from "../middleware/clientIdentity.js";

/**
 * @fileoverview Parses the campus-network whitelist - ENABLE_IP_WHITELIST and
 * ALLOWED_ADMIN_IPS, enforced by middleware/ipWhitelistMiddleware.js - and
 * describes it for the startup log.
 *
 * Each comma-separated ALLOWED_ADMIN_IPS entry is a single address or a CIDR
 * range:
 *
 *   ALLOWED_ADMIN_IPS=127.0.0.1,::1,203.0.113.0/24,2001:db8:abcd::/48
 *
 * Ranges exist because a campus network is rarely one address. A
 * university's NAT gateway often spreads outbound connections over a pool of
 * public IPs, so checking api.ipify.org twice at the venue can return
 * 203.0.113.17 and then 203.0.113.42. With exact addresses only, the second
 * is refused - and the refusal also blocks that IP for
 * securityConfig.mitigation.temporaryBlockMs, so student sign-ins from the
 * venue go down with it. "203.0.113.0/24" covers the whole pool: the first 24
 * of the address's 32 bits must match, which admits 2^(32-24) = 256 addresses,
 * 203.0.113.0 through 203.0.113.255.
 *
 * Matching uses node:net's BlockList, Node's built-in matcher for addresses
 * and subnets. Its name comes from its usual job; here it is used the other
 * way round, and check() answering true means "on the allowed list".
 *
 * Two rules keep a typo from ever widening access:
 *
 *   1. An entry that is not a valid address or CIDR range is ignored, with a
 *      startup warning. Ignoring an entry can only shrink the allowed set, so
 *      a malformed one fails closed while the other entries keep working. It
 *      never stops the server from starting: like config/databaseUrl.js,
 *      problems here are warnings, because a server that refuses to start
 *      takes the Student Portal down with it.
 *
 *   2. A range broader than /16 (IPv4) or /32 (IPv6) is ignored the same
 *      way. A /16 is already 65,536 addresses - more than one campus needs -
 *      while "/2" typed for "/24" would admit a quarter of the IPv4 internet
 *      (2^30 addresses). Turning enforcement off is what
 *      ENABLE_IP_WHITELIST=false is for; "0.0.0.0/0" is not a way to do it.
 */

/** The broadest range accepted per address family - see rule 2 in this file's @fileoverview. */
export const MIN_PREFIX_LENGTH = { ipv4: 16, ipv6: 32 };

/** Bits in an address, and so the longest valid prefix ("/32" is a single IPv4 address). */
const MAX_PREFIX_LENGTH = { ipv4: 32, ipv6: 128 };

/**
 * @param {Record<string, string|undefined>} env - Usually process.env.
 * @returns {boolean} Whether whitelist enforcement is active. Anything other than the literal string "true" (case-insensitive) - including the variable being unset - is treated as disabled, so a missing or malformed value fails open rather than locking every admin out.
 */
export function isWhitelistEnabled(env) {
    return (env.ENABLE_IP_WHITELIST || '').trim().toLowerCase() === 'true';
}

/**
 * @param {string} address
 * @returns {"ipv4"|"ipv6"|null}
 */
function ipFamily(address) {
    if (isIPv4(address)) return 'ipv4';
    if (isIPv6(address)) return 'ipv6';
    return null;
}

/**
 * Adds one ALLOWED_ADMIN_IPS entry to `blockList`, or explains why it cannot.
 *
 * The address part goes through normalizeIp() first, the same as every
 * request's req.ip, so an entry written in IPv4-mapped form
 * ("::ffff:10.0.0.5") matches the plain IPv4 address it stands for.
 *
 * @param {BlockList} blockList
 * @param {string} entry - A trimmed, non-empty entry, e.g. "10.0.0.5" or "203.0.113.0/24".
 * @returns {string|null} Why the entry was ignored, or null if it was added.
 */
function addEntry(blockList, entry) {
    const [rawAddress, prefixText, ...extra] = entry.split('/');
    const address = normalizeIp(rawAddress);
    const family = ipFamily(address);
    if (!family || extra.length) return 'not an IP address or CIDR range';

    if (prefixText === undefined) {
        blockList.addAddress(address, family);
        return null;
    }

    const prefix = /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : NaN;
    if (!(prefix <= MAX_PREFIX_LENGTH[family])) {
        return `"/${prefixText}" is not a valid ${family === 'ipv4' ? 'IPv4' : 'IPv6'} prefix length`;
    }
    if (prefix < MIN_PREFIX_LENGTH[family]) {
        return `/${prefix} is broader than the /${MIN_PREFIX_LENGTH[family]} limit`;
    }

    blockList.addSubnet(address, prefix, family);
    return null;
}

/**
 * @param {string|undefined} raw - ALLOWED_ADMIN_IPS as set.
 * @returns {{blockList: BlockList, entries: string[], warnings: string[]}}
 *          The matcher, the entries it holds (as written), and one warning per ignored entry.
 */
export function parseAllowedAdminNetworks(raw) {
    const blockList = new BlockList();
    const entries = [];
    const warnings = [];

    for (const entry of (raw ?? '').split(',').map(part => part.trim()).filter(Boolean)) {
        const problem = addEntry(blockList, entry);
        if (problem) warnings.push(`ALLOWED_ADMIN_IPS entry "${entry}" ignored - ${problem}.`);
        else entries.push(entry);
    }

    return { blockList, entries, warnings };
}

/**
 * @param {BlockList} blockList - From parseAllowedAdminNetworks().
 * @param {string|undefined} ip - A normalized request address (middleware/clientIdentity.js#normalizeIp).
 * @returns {boolean} Whether `ip` is a whitelisted address or falls inside a whitelisted range. A missing or malformed address is never allowed.
 */
export function isAllowedAdminIp(blockList, ip) {
    const family = typeof ip === 'string' ? ipFamily(ip) : null;
    return family !== null && blockList.check(ip, family);
}

/**
 * The whitelist as the server will enforce it, for the startup log. On
 * defense morning, after ALLOWED_ADMIN_IPS is updated on Render, this line is
 * how to confirm the new venue range took effect before opening the Admin
 * Portal.
 *
 * @param {Record<string, string|undefined>} env - Usually process.env.
 * @returns {{summary: string, warnings: string[]}} e.g. "on - 127.0.0.1, 203.0.113.0/24", and anything worth fixing.
 */
export function describeAdminWhitelist(env) {
    const enabled = isWhitelistEnabled(env);
    const { entries, warnings } = parseAllowedAdminNetworks(env.ALLOWED_ADMIN_IPS);

    if (enabled && entries.length === 0) {
        warnings.push('ENABLE_IP_WHITELIST=true but ALLOWED_ADMIN_IPS has no valid entries - the Admin Portal is refused from every address.');
    }

    return { summary: `${enabled ? 'on' : 'off'} - ${entries.join(', ') || 'no valid entries'}`, warnings };
}
