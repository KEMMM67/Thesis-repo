/**
 * @fileoverview Default IdentityResolver (see core/ports.js), backed by
 * Prisma's `user` table.
 *
 * Extracted from middleware/securityMiddleware.js (which looked up a
 * user's id, purely to attribute audit rows, on every authenticated
 * request) and middleware/ipWhitelistMiddleware.js (which looked up a
 * user's role to decide whether the admin-login network gate applies).
 * Both now call this one class instead of running their own query.
 */
export class PrismaIdentityResolver {
    /** @param {import("@prisma/client").PrismaClient} prisma */
    constructor(prisma) {
        this.prisma = prisma;
    }

    /**
     * @param {string} email
     * @returns {Promise<import("../../core/ports.js").ResolvedIdentity|null>}
     */
    async resolve(email) {
        const user = await this.prisma.user.findUnique({ where: { email }, select: { id: true, role: true } });
        return user ? { id: user.id, role: user.role } : null;
    }
}
