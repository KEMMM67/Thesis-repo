import { describe, it, expect } from 'vitest';
import { Writable } from 'node:stream';
import { finished } from 'node:stream/promises';
import { streamDatabaseExport } from './databaseExport.js';

const range = (n, make) => Array.from({ length: n }, (_, i) => make(i + 1));

/** In-memory stand-in for one Prisma model: supports the keyset query the export issues. */
function fakeModel(rows) {
    return {
        async findMany({ where, orderBy, take, select }) {
            expect(orderBy).toEqual({ id: 'asc' });
            let page = rows.filter(r => r.id > where.id.gt).sort((a, b) => a.id - b.id).slice(0, take);
            if (select) {
                page = page.map(r => Object.fromEntries(Object.keys(select).filter(k => select[k]).map(k => [k, r[k]])));
            }
            return page;
        }
    };
}

function fakeDb(tables) {
    const db = {
        user: fakeModel(tables.users ?? []),
        student: fakeModel(tables.students ?? []),
        subject: fakeModel(tables.subjects ?? []),
        loginAttempt: fakeModel(tables.loginAttempts ?? []),
        anomalyScore: fakeModel(tables.anomalyScores ?? []),
        securityAction: fakeModel(tables.securityActions ?? []),
        behaviorLog: fakeModel(tables.behaviorLogs ?? []),
        ipTracking: fakeModel(tables.ipTracking ?? []),
        auditLog: fakeModel(tables.auditLogs ?? []),
        rawSql: [],
        transactionOptions: [],
        async $queryRaw(strings, afterId, take) {
            db.rawSql.push(strings.join('?'));
            return (tables.grades ?? []).filter(g => g.id > afterId).slice(0, take);
        },
        async $transaction(fn, options) {
            db.transactionOptions.push(options);
            return fn(db);
        }
    };
    return db;
}

/** Collects everything written; `slow` delays each write callback so write() returns false and 'drain' is exercised. */
function collector({ highWaterMark = 16 * 1024, slow = false } = {}) {
    const chunks = [];
    const stream = new Writable({
        highWaterMark,
        write(chunk, _encoding, callback) {
            chunks.push(chunk.toString());
            if (slow) setImmediate(callback); else callback();
        }
    });
    stream.text = () => chunks.join('');
    return stream;
}

const meta = { generatedBy: 'admin@example.edu.ph', generatedAt: new Date('2026-09-24T12:00:00Z') };

/** Runs the export the way the route does - then ends the stream and waits for every buffered chunk to land. */
async function exportTo(db, out, options = {}) {
    await streamDatabaseExport(db, out, { ...meta, ...options });
    out.end();
    await finished(out);
    return out.text();
}

describe('streamDatabaseExport', () => {
    it('writes every table as one valid JSON document, all rows in id order across batch boundaries', async () => {
        const db = fakeDb({
            users: range(12, id => ({ id, email: `u${id}@x.edu.ph`, role: 'student', createdAt: new Date(0) })),
            students: range(10, id => ({ id, studentId: `CC25-${String(id).padStart(6, '0')}` })),
            subjects: range(3, id => ({ id, subjectCode: `S${id}` }))
        });
        const snapshot = JSON.parse(await exportTo(db, collector(), { batchSize: 5 }));

        expect(snapshot.format).toBe('sis-json-snapshot/v1');
        expect(snapshot.generatedBy).toBe('admin@example.edu.ph');
        expect(snapshot.users.map(u => u.id)).toEqual(range(12, id => id));      // 5 + 5 + 2
        expect(snapshot.students.map(s => s.id)).toEqual(range(10, id => id));   // 5 + 5 + an empty last page
        expect(snapshot.subjects).toHaveLength(3);
        expect(snapshot.ipTracking).toEqual([]);
        expect(Object.keys(snapshot)).toEqual([
            'format', 'generatedAt', 'generatedBy', 'consistency', 'encryption',
            'users', 'students', 'subjects', 'grades', 'loginAttempts', 'anomalyScores', 'securityActions', 'behaviorLogs', 'ipTracking', 'auditLogs'
        ]);
    });

    it('never exports password hashes or OTP codes', async () => {
        const db = fakeDb({ users: [{ id: 1, email: 'a@x.edu.ph', role: 'admin', createdAt: new Date(0), passwordHash: '$2b$10$secret', otpCode: '123456' }] });
        const text = await exportTo(db, collector());

        expect(JSON.parse(text).users).toEqual([{ id: 1, email: 'a@x.edu.ph', role: 'admin', createdAt: new Date(0).toISOString() }]);
        expect(text).not.toContain('secret');
        expect(text).not.toContain('123456');
    });

    it('exports grades exactly as stored - still encrypted - through raw SQL on the grades table', async () => {
        const envelope = 'MTIzNDU2Nzg5MDEy:dGFndGFndGFndGFndGFn:Y2lwaGVy';
        const db = fakeDb({ grades: [{ id: 1, studentId: 1, subjectId: 1, term: 'T1', grade: envelope, remarks: 'Passed' }] });
        const text = await exportTo(db, collector());

        expect(JSON.parse(text).grades[0].grade).toBe(envelope);
        expect(db.rawSql.every(sql => /FROM grades/.test(sql))).toBe(true);
    });

    it('reads everything inside one REPEATABLE READ transaction', async () => {
        const db = fakeDb({});
        await exportTo(db, collector());

        expect(db.transactionOptions).toHaveLength(1);
        expect(db.transactionOptions[0].isolationLevel).toBe('RepeatableRead');
    });

    it('waits for the stream to drain instead of buffering rows', async () => {
        const db = fakeDb({ behaviorLogs: range(50, id => ({ id, description: 'x'.repeat(200) })) });
        const text = await exportTo(db, collector({ highWaterMark: 64, slow: true }), { batchSize: 7 });

        expect(JSON.parse(text).behaviorLogs).toHaveLength(50);
    });

    it('rejects if the download is cancelled mid-export, so the caller can abort instead of ending the file', async () => {
        const db = fakeDb({ students: range(20, id => ({ id })) });
        const stalled = new Writable({ highWaterMark: 1, write() { /* never completes */ } });

        const exporting = streamDatabaseExport(db, stalled, meta);
        setTimeout(() => stalled.destroy(), 10);

        await expect(exporting).rejects.toThrow(/closed before the snapshot finished/);
    });
});
