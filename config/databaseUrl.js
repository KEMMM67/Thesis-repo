/**
 * @fileoverview Reports, at startup, how Prisma will connect to PostgreSQL -
 * the connection settings carried as query parameters on DATABASE_URL -
 * without ever printing the URL itself (it holds the database password).
 *
 * On Render, DATABASE_URL points at the AWS RDS instance and is typed by hand
 * into the dashboard, so a dropped parameter is easy to miss and nothing else
 * would ever reveal it. Two of them matter there:
 *
 *   - sslmode=require: refuse to connect without TLS. Prisma's default,
 *     "prefer", silently falls back to plaintext if TLS cannot be agreed,
 *     and this connection crosses the public internet from Render to AWS.
 *     (RDS for PostgreSQL 15+ also enforces TLS on its side, rds.force_ssl=1;
 *     this makes the client insist too, whatever the server is set to.)
 *
 *   - connection_limit: Prisma otherwise sizes its pool from the CPU count it
 *     can see (num_cpus * 2 + 1), which on a shared host is the machine's,
 *     not this service's share of it. An explicit limit keeps the pool
 *     predictable against a micro RDS instance's ~80-110 connection ceiling,
 *     which also has to serve seed scripts and a local Plan B server.
 *
 * Missing values only produce a warning, never a startup failure: on a live
 * defense, a server that starts with a weaker connection beats one that
 * refuses to start. Like config/trustProxy.js, warnings apply only on Render
 * (RENDER=true) - a local DATABASE_URL pointing at localhost needs neither.
 */

/** Pool size recommended for the single Render instance - see this file's @fileoverview. */
export const RECOMMENDED_CONNECTION_LIMIT = 10;

/**
 * @param {Record<string, string|undefined>} env - Usually process.env.
 * @returns {{summary: string, warnings: string[]}} A one-line, credential-free description for the startup log, and anything worth fixing.
 */
export function describeDatabaseUrl(env) {
    const raw = (env.DATABASE_URL ?? '').trim();
    if (!raw) {
        return { summary: 'DATABASE_URL is not set', warnings: ['DATABASE_URL is not set - every database query will fail.'] };
    }

    let url;
    try {
        url = new URL(raw);
    } catch {
        return { summary: 'DATABASE_URL is not a valid URL', warnings: ['DATABASE_URL could not be parsed - check it for unencoded special characters in the password (e.g. @ must be %40).'] };
    }

    const sslmode = url.searchParams.get('sslmode');
    const connectionLimit = url.searchParams.get('connection_limit');
    const poolTimeout = url.searchParams.get('pool_timeout');

    const summary = [
        `sslmode=${sslmode ?? 'prefer (Prisma default)'}`,
        `connection_limit=${connectionLimit ?? 'Prisma default (CPU-based)'}`,
        `pool_timeout=${poolTimeout ?? '10s (Prisma default)'}`
    ].join(', ');

    const warnings = [];
    if ((env.RENDER ?? '').trim().toLowerCase() === 'true') {
        if (sslmode !== 'require') {
            warnings.push('DATABASE_URL has no sslmode=require - the connection to RDS may fall back to plaintext.');
        }
        if (connectionLimit === null) {
            warnings.push(`DATABASE_URL has no connection_limit - add connection_limit=${RECOMMENDED_CONNECTION_LIMIT} so the pool size does not depend on the host's CPU count.`);
        }
    }

    return { summary, warnings };
}
