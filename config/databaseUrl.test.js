import { describe, it, expect } from 'vitest';
import { describeDatabaseUrl } from './databaseUrl.js';

const RDS = 'postgresql://sis_admin:s3cr%40t@sis-db.abc123.ap-southeast-1.rds.amazonaws.com:5432/sis';

describe('describeDatabaseUrl', () => {
    it('reports a fully configured Render URL with no warnings', () => {
        const { summary, warnings } = describeDatabaseUrl({
            RENDER: 'true',
            DATABASE_URL: `${RDS}?sslmode=require&connection_limit=10&pool_timeout=20`
        });
        expect(summary).toBe('sslmode=require, connection_limit=10, pool_timeout=20');
        expect(warnings).toEqual([]);
    });

    it('warns on Render when TLS or the pool limit is missing', () => {
        const { warnings } = describeDatabaseUrl({ RENDER: 'true', DATABASE_URL: RDS });
        expect(warnings).toHaveLength(2);
        expect(warnings.join(' ')).toMatch(/sslmode=require/);
        expect(warnings.join(' ')).toMatch(/connection_limit=10/);
    });

    it('does not warn about a plain local database', () => {
        const { summary, warnings } = describeDatabaseUrl({ DATABASE_URL: 'postgresql://postgres:pw@localhost:5432/sis' });
        expect(summary).toMatch(/prefer \(Prisma default\)/);
        expect(warnings).toEqual([]);
    });

    it('never puts the user, password or host in the log line', () => {
        const { summary, warnings } = describeDatabaseUrl({ RENDER: 'true', DATABASE_URL: RDS });
        const logged = [summary, ...warnings].join(' ');
        for (const secret of ['sis_admin', 's3cr', 'rds.amazonaws.com']) {
            expect(logged).not.toContain(secret);
        }
    });

    it('reports a missing or unparseable URL instead of throwing', () => {
        expect(describeDatabaseUrl({}).warnings[0]).toMatch(/not set/);
        expect(describeDatabaseUrl({ DATABASE_URL: 'not a url' }).warnings[0]).toMatch(/could not be parsed/);
    });
});
