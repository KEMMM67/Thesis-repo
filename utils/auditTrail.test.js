import 'dotenv/config';
import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'crypto';
import {
    GENESIS_HASH, appendAuditEntry, withAudit, recordAudit, verifyAuditChain,
    diffFields, readAuditDetail, sealEntry, canonicalEntry
} from './auditTrail.js';

/**
 * @fileoverview The audit trail's chain, against an in-memory fake of the
 * audit_logs table - the same no-database approach as
 * utils/databaseExport.test.js. The fake has no triggers, so a test can
 * play the part of someone who has already disabled them and edits rows
 * directly; the chain must still catch it.
 *
 * Requires FIELD_ENCRYPTION_KEY (see .env), like fieldEncryption.test.js:
 * `detail` is encrypted, and the HMAC key is derived from it.
 */

function fakeDb() {
    const rows = [];
    const auditLog = {
        findFirst: async () => (rows.length ? { hash: rows[rows.length - 1].hash } : null),
        create: async ({ data }) => {
            const row = { id: rows.length ? rows[rows.length - 1].id + 1 : 1, ...data };
            rows.push(row);
            return row;
        },
        findMany: async ({ where, take }) => rows.filter(row => row.id > where.id.gt).slice(0, take)
    };
    const tx = { auditLog, $executeRaw: async () => 1 };
    return { rows, auditLog, $transaction: async (fn) => fn(tx), tx };
}

function entry(overrides = {}) {
    return {
        actorUserId: 1,
        actorEmail: 'admin@x.edu.ph',
        actorRole: 'admin',
        action: 'GRADE_UPDATE',
        entityType: 'Grade',
        entityId: 'A23-00001 · SE301 · 1st Sem',
        outcome: 'SUCCESS',
        statusCode: 200,
        ipAddress: '203.0.113.7',
        deviceId: 'DEV-1a2b',
        detail: { changes: { grade: { from: '1.25', to: '3.00' } } },
        ...overrides
    };
}

async function chainOf(count) {
    const db = fakeDb();
    for (let i = 0; i < count; i++) {
        await appendAuditEntry(db.tx, entry({ entityId: `A23-0000${i + 1} · SE301` }));
    }
    return db;
}

describe('appendAuditEntry', () => {
    it('links each entry to the one before it, starting from the genesis hash', async () => {
        const db = await chainOf(3);
        expect(db.rows[0].prevHash).toBe(GENESIS_HASH);
        expect(db.rows[1].prevHash).toBe(db.rows[0].hash);
        expect(db.rows[2].prevHash).toBe(db.rows[1].hash);
        expect(db.rows[0].hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('stores the change details encrypted, never as plaintext grades', async () => {
        const db = await chainOf(1);
        expect(db.rows[0].detail).not.toContain('1.25');
        expect(db.rows[0].detail).not.toContain('grade');
        expect(readAuditDetail(db.rows[0].detail)).toEqual({ detail: { changes: { grade: { from: '1.25', to: '3.00' } } }, readable: true });
    });

    it('takes the append lock before reading the previous entry', async () => {
        const db = fakeDb();
        const calls = [];
        db.tx.$executeRaw = async () => { calls.push('lock'); return 1; };
        const findFirst = db.auditLog.findFirst;
        db.auditLog.findFirst = async (args) => { calls.push('read previous'); return findFirst(args); };
        await appendAuditEntry(db.tx, entry());
        expect(calls).toEqual(['lock', 'read previous']);
    });
});

describe('verifyAuditChain', () => {
    it('verifies an untouched chain and reports its length and newest seal', async () => {
        const db = await chainOf(5);
        expect(await verifyAuditChain(db, { batchSize: 2 })).toEqual({ intact: true, checked: 5, headHash: db.rows[4].hash });
    });

    it('reports an empty trail as intact, with no head', async () => {
        expect(await verifyAuditChain(fakeDb())).toEqual({ intact: true, checked: 0, headHash: null });
    });

    it('catches an entry edited after it was written, at that entry', async () => {
        const db = await chainOf(4);
        db.rows[1].entityId = 'A23-09999 · SE301';
        const result = await verifyAuditChain(db);
        expect(result).toMatchObject({ intact: false, checked: 1, brokenAt: 2 });
        expect(result.reason).toMatch(/changed after it was written/);
    });

    it('catches a deleted entry, at the entry after the gap', async () => {
        const db = await chainOf(4);
        db.rows.splice(1, 1);
        const result = await verifyAuditChain(db);
        expect(result).toMatchObject({ intact: false, checked: 1, brokenAt: 3 });
        expect(result.reason).toMatch(/deleted, inserted or reordered/);
    });

    it('catches swapped encrypted details, even though each still decrypts', async () => {
        const db = await chainOf(3);
        [db.rows[0].detail, db.rows[1].detail] = [db.rows[1].detail, db.rows[0].detail];
        expect(await verifyAuditChain(db)).toMatchObject({ intact: false, brokenAt: 1 });
    });

    it('cannot be fooled by re-sealing the chain without the key', async () => {
        // Someone with database access but not the application's key edits
        // entry #2, then recomputes every seal from there on with the best
        // they have - plain SHA-256 - to cover it up.
        const db = await chainOf(3);
        db.rows[1].entityId = 'A23-09999 · SE301';
        for (let i = 1; i < db.rows.length; i++) {
            db.rows[i].prevHash = db.rows[i - 1].hash;
            db.rows[i].hash = createHash('sha256').update(canonicalEntry(db.rows[i])).digest('hex');
        }
        expect(await verifyAuditChain(db)).toMatchObject({ intact: false, brokenAt: 2 });
    });

    it('depends on the key: the same rows do not verify under a different one', async () => {
        const db = await chainOf(2);
        expect(await verifyAuditChain(db, { key: Buffer.alloc(32, 7) })).toMatchObject({ intact: false, brokenAt: 1 });
    });
});

describe('withAudit', () => {
    it('records the change as a SUCCESS entry, with the key the change resolved', async () => {
        const db = fakeDb();
        const result = await withAudit(db, { ...entry(), entityId: '17', statusCode: 201, detail: undefined }, async () => ({
            result: 'saved',
            entityId: 'A23-00001 · SE301',
            detail: { changes: { grade: { from: null, to: '1.00' } } }
        }));
        expect(result).toBe('saved');
        expect(db.rows).toHaveLength(1);
        expect(db.rows[0]).toMatchObject({ outcome: 'SUCCESS', statusCode: 201, entityId: 'A23-00001 · SE301' });
    });

    it('writes nothing when the change itself fails, and passes its error through', async () => {
        const db = fakeDb();
        const notFound = Object.assign(new Error('Record not found'), { code: 'P2025' });
        await expect(withAudit(db, entry(), async () => { throw notFound; })).rejects.toBe(notFound);
        expect(db.rows).toHaveLength(0);
    });
});

describe('recordAudit', () => {
    it('never throws, so a failed audit write cannot break the response', async () => {
        const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
        const db = { $transaction: async () => { throw new Error('connection reset'); } };
        await expect(recordAudit(db, entry({ outcome: 'FAILURE', statusCode: 404 }))).resolves.toBeUndefined();
        expect(errors).toHaveBeenCalledWith(expect.stringContaining('[AUDIT]'), 'connection reset');
        errors.mockRestore();
    });
});

describe('readAuditDetail', () => {
    it('reports tampered ciphertext as unreadable instead of throwing', async () => {
        const db = await chainOf(1);
        const [iv, tag, cipher] = db.rows[0].detail.split(':');
        const flipped = Buffer.from(cipher, 'base64');
        flipped[0] ^= 1;
        expect(readAuditDetail([iv, tag, flipped.toString('base64')].join(':'))).toEqual({ detail: null, readable: false });
        expect(readAuditDetail(null)).toEqual({ detail: null, readable: true });
    });
});

describe('diffFields', () => {
    const FIELDS = ['fullName', 'department', 'units'];

    it('lists every field that was set on a created record', () => {
        expect(diffFields(null, { fullName: 'CRUZ, Ana', department: '', units: 3 }, FIELDS))
            .toEqual({ fullName: { from: null, to: 'CRUZ, Ana' }, units: { from: null, to: 3 } });
    });

    it('lists only the fields an update changed', () => {
        expect(diffFields({ fullName: 'CRUZ, Ana', department: 'CCMS', units: 3 }, { fullName: 'CRUZ, Ana Marie', department: 'CCMS', units: '3' }, FIELDS))
            .toEqual({ fullName: { from: 'CRUZ, Ana', to: 'CRUZ, Ana Marie' } });
    });

    it('lists every field a deleted record had', () => {
        expect(diffFields({ fullName: 'CRUZ, Ana', department: 'CCMS', units: 3 }, null, FIELDS))
            .toEqual({ fullName: { from: 'CRUZ, Ana', to: null }, department: { from: 'CCMS', to: null }, units: { from: 3, to: null } });
    });
});

describe('sealEntry', () => {
    it('changes when any sealed field changes', () => {
        const base = { ...entry(), detail: 'x', occurredAt: new Date('2026-10-05T02:00:00Z'), prevHash: GENESIS_HASH };
        const seal = sealEntry(base);
        for (const [field, value] of [['actorEmail', 'other@x.edu.ph'], ['statusCode', 500], ['occurredAt', new Date('2026-10-05T02:00:01Z')], ['detail', 'y'], ['prevHash', '1'.repeat(64)]]) {
            expect(sealEntry({ ...base, [field]: value }), field).not.toBe(seal);
        }
    });
});
