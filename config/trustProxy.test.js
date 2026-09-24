import { describe, it, expect } from 'vitest';
import { resolveTrustProxy } from './trustProxy.js';

describe('resolveTrustProxy', () => {
    it('trusts no forwarded header by default, so a local or LAN client cannot choose its own IP', () => {
        expect(resolveTrustProxy({}).hops).toBe(0);
    });

    it("uses Render's 3 hops automatically when Render's own RENDER=true is present", () => {
        expect(resolveTrustProxy({ RENDER: 'true' }).hops).toBe(3);
    });

    it('lets TRUST_PROXY_HOPS override both, including 0 on Render', () => {
        expect(resolveTrustProxy({ TRUST_PROXY_HOPS: '2' }).hops).toBe(2);
        expect(resolveTrustProxy({ TRUST_PROXY_HOPS: '0', RENDER: 'true' }).hops).toBe(0);
    });

    it('fails loudly on a value that would silently weaken the whitelist', () => {
        for (const bad of ['true', '-1', '1.5', 'three', '11']) {
            expect(() => resolveTrustProxy({ TRUST_PROXY_HOPS: bad }), bad).toThrow(/TRUST_PROXY_HOPS/);
        }
    });
});
