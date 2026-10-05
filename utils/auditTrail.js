import { createHmac, timingSafeEqual } from "crypto";
import { encryptField, decryptField, deriveKey } from "../adapters/prisma/fieldEncryption.js";

/**
 * @fileoverview The administrative audit trail: a permanent,
 * tamper-evident record of every change an administrator makes to the
 * system - student, subject and grade records, admin accounts, WEVA
 * blocks, database exports - stored in the audit_logs table
 * (prisma/schema.prisma#AuditLog).
 *
 * It answers a different question from the Security Events log
 * (behavior_logs, written by WEVA): that log records how a device or
 * account *behaved* - its request rate, its failed logins, the verdict
 * WEVA reached. This one records what an administrator *did*: "who changed
 * A23-00001's grade in SE301, from what, to what, and from where?"
 *
 * ---- What one entry records ----
 *
 *   who     actorUserId, actorEmail, actorRole - from the verified JWT and
 *           Session row (middleware/authMiddleware.js), never from the
 *           request body
 *   what    action (e.g. GRADE_UPDATE), entityType, and entityId - the
 *           record's human-readable key (student ID, subject code, ...),
 *           so an auditor can search for "A23-00001" directly
 *   how     detail - which fields changed, from what, to what
 *   result  outcome + statusCode - refused and failed attempts too
 *   where   ipAddress, deviceId - the same identities WEVA scores
 *   when    occurredAt
 *
 * ---- Atomic with the change it describes ----
 *
 * withAudit() runs a change and its audit entry in one database
 * transaction, so both commit or neither does. If the entry cannot be
 * written, the change is rolled back and the administrator gets an error:
 * an audit trail that can silently miss a change cannot be trusted to say
 * who made one. Refused and failed attempts (404, 409, 500) have no change
 * to roll back, so recordAudit() writes them on a best-effort basis.
 *
 * ---- Tamper evidence: an HMAC chain ----
 *
 * Every entry is sealed: `hash` is an HMAC-SHA256 over the entry's own
 * contents *including the previous entry's hash* (`prevHash`; 64 zeros
 * for the very first entry). Each seal therefore depends on every entry
 * before it:
 *
 *   #1  prevHash 000...0   hash H1 = HMAC(k, [#1's fields, 000...0])
 *   #2  prevHash H1        hash H2 = HMAC(k, [#2's fields, H1])
 *   #3  prevHash H2        hash H3 = HMAC(k, [#3's fields, H2])
 *
 * verifyAuditChain() walks the chain from #1 and recomputes every seal:
 *
 *   - Edit #2 (e.g. change its grade from 1.25 to 3.00): #2's recomputed
 *     seal no longer equals the stored H2 -> "modified" at #2.
 *   - Delete #2: #3's prevHash is H2, but the entry before #3 is now #1,
 *     whose hash is H1 -> "broken link" at #3. Inserting or reordering
 *     entries breaks a link the same way.
 *   - Edit #2 and re-seal #2 and #3 to cover it up: this needs k.
 *
 * That last case is why the seal is an HMAC rather than a plain SHA-256.
 * Anyone who can write to the database can compute SHA-256, so a plain
 * hash chain only proves the rows are consistent with each other - an
 * attacker could edit a row and simply recompute every hash after it. An
 * HMAC can only be computed with its key, which lives in the
 * application's environment (derived from FIELD_ENCRYPTION_KEY - see
 * adapters/prisma/fieldEncryption.js#deriveKey), never in the database. A
 * stolen database password, or a rogue DBA, is not enough to forge it.
 *
 * Defense in depth: the database itself refuses UPDATE, DELETE and
 * TRUNCATE on audit_logs (triggers in this table's migration), so the
 * chain is the second line - it catches what happens after someone with
 * superuser rights turns those triggers off.
 *
 * What the chain cannot catch on its own: removing the *newest* entries
 * leaves a shorter chain that still verifies. Verification therefore
 * reports how many entries it checked and the newest seal (the "head");
 * the printed audit report records both, so a later report with fewer
 * entries, or a different seal at the same entry, exposes the truncation.
 * Anchoring the head outside the system entirely (e.g. emailing it daily)
 * would close that gap - future work.
 *
 * ---- Why `detail` is encrypted here, explicitly ----
 *
 * A grade change records the grades themselves, and grades are encrypted
 * at rest (adapters/prisma/fieldEncryption.js). Storing them in plaintext
 * here would quietly undo that, so `detail` is AES-256-GCM ciphertext
 * too. It is encrypted in this file, before sealing, rather than by
 * listing AuditLog in fieldEncryption's ENCRYPTED_FIELDS: the seal must
 * cover exactly the bytes stored in the database, so verification can
 * recompute it from the raw rows without decrypting anything.
 */

/** prevHash of the first entry ever written. */
export const GENESIS_HASH = "0".repeat(64);

/**
 * Hashed into every seal, so a future change to the canonical form below
 * can never produce a seal that verifies under this one.
 */
const CHAIN_FORMAT = "sis-audit-v1";

/**
 * Postgres advisory-lock id reserved for appending to the chain. Any fixed
 * 64-bit integer works; this one is "AUDT" in ASCII.
 */
const APPEND_LOCK_ID = 0x41554454;

let chainKeyCache = null;

/** @returns {Buffer} The HMAC key, derived once from FIELD_ENCRYPTION_KEY. */
function chainKey() {
    chainKeyCache ??= deriveKey("audit-chain-v1");
    return chainKeyCache;
}

/**
 * The exact byte string an entry's seal covers. A JSON array with a fixed
 * field order: positions are fixed and every string is quoted and escaped,
 * so two different entries can never produce the same text - unlike plain
 * concatenation, where actorEmail "ab" + action "c" and "a" + "bc" would
 * collide.
 *
 * @param {object} entry - An audit_logs row, or one about to be written.
 * @returns {string}
 */
export function canonicalEntry(entry) {
    return JSON.stringify([
        CHAIN_FORMAT,
        entry.occurredAt.toISOString(),
        entry.actorUserId ?? null,
        entry.actorEmail,
        entry.actorRole,
        entry.action,
        entry.entityType,
        entry.entityId,
        entry.outcome,
        entry.statusCode,
        entry.ipAddress ?? null,
        entry.deviceId ?? null,
        entry.detail ?? null,
        entry.prevHash
    ]);
}

/**
 * @param {object} entry - See canonicalEntry().
 * @param {Buffer} [key] - Defaults to the application's chain key; tests pass their own.
 * @returns {string} The entry's seal: HMAC-SHA256, hex-encoded.
 */
export function sealEntry(entry, key = chainKey()) {
    return createHmac("sha256", key).update(canonicalEntry(entry)).digest("hex");
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {boolean} Whether two hex seals are equal, compared in constant time.
 */
function sealsMatch(a, b) {
    const left = Buffer.from(a, "hex");
    const right = Buffer.from(b, "hex");
    return left.length === right.length && timingSafeEqual(left, right);
}

/** Missing and blank values both mean "no value", so "" -> null is not reported as a change. */
function blankToNull(value) {
    return value === undefined || value === null || value === "" ? null : value;
}

/**
 * Lists the fields that differ between two versions of a record, for an
 * entry's `detail.changes`. One shape covers all three kinds of change:
 *
 *   create   diffFields(null, created, fields)  -> every field that was set, from null
 *   update   diffFields(before, after, fields)  -> only the fields that changed
 *   delete   diffFields(removed, null, fields)  -> every field the record had, to null
 *
 * Values are compared as strings, so 3 and "3" are the same value.
 *
 * @param {object|null} before
 * @param {object|null} after
 * @param {string[]} fields - The fields worth recording - never secrets such as passwordHash.
 * @returns {Record<string, {from: *, to: *}>}
 */
export function diffFields(before, after, fields) {
    const changes = {};
    for (const field of fields) {
        const from = blankToNull(before?.[field]);
        const to = blankToNull(after?.[field]);
        if (from === null && to === null) continue;
        if (from !== null && to !== null && String(from) === String(to)) continue;
        changes[field] = { from, to };
    }
    return changes;
}

/**
 * Appends one sealed entry to the chain. Must run inside an interactive
 * transaction (`tx`), because of the lock below.
 *
 * Two administrators saving at the same instant must not both read the
 * same previous entry and both link to it - the chain would fork, and one
 * branch would fail verification forever. A transaction-level advisory
 * lock serializes appends: the second transaction waits at the lock until
 * the first commits (Postgres releases it then, automatically), and only
 * then reads the newest entry - which, under READ COMMITTED, is now the
 * first transaction's. The lock is taken last, just before reading the
 * newest entry, so it is held only for this append, not for the change
 * that came before it in the same transaction.
 *
 * @param {object} tx - Prisma interactive-transaction client.
 * @param {object} fields
 * @param {number|null} fields.actorUserId
 * @param {string} fields.actorEmail
 * @param {string} fields.actorRole
 * @param {string} fields.action - e.g. "GRADE_UPDATE".
 * @param {string} fields.entityType - e.g. "Grade".
 * @param {string} fields.entityId - The record's human-readable key, at most 150 characters.
 * @param {"SUCCESS"|"FAILURE"} fields.outcome
 * @param {number} fields.statusCode - The HTTP status the administrator received.
 * @param {string|null} [fields.ipAddress]
 * @param {string|null} [fields.deviceId]
 * @param {{changes?: object, note?: string}|null} [fields.detail] - Encrypted before it is stored.
 * @returns {Promise<object>} The stored row.
 */
export async function appendAuditEntry(tx, fields) {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${APPEND_LOCK_ID}::bigint)`;
    const previous = await tx.auditLog.findFirst({ orderBy: { id: "desc" }, select: { hash: true } });

    const entry = {
        occurredAt: new Date(),
        actorUserId: fields.actorUserId ?? null,
        actorEmail: fields.actorEmail,
        actorRole: fields.actorRole,
        action: fields.action,
        entityType: fields.entityType,
        entityId: fields.entityId,
        outcome: fields.outcome,
        statusCode: fields.statusCode,
        ipAddress: fields.ipAddress ?? null,
        deviceId: fields.deviceId ?? null,
        detail: fields.detail == null ? null : encryptField(JSON.stringify(fields.detail)),
        prevHash: previous?.hash ?? GENESIS_HASH
    };

    return tx.auditLog.create({ data: { ...entry, hash: sealEntry(entry) } });
}

/**
 * Runs `change` and records it as a SUCCESS entry, in one transaction:
 * if either fails, neither is kept (see this file's @fileoverview).
 *
 * `change` receives the transaction client and must make every write
 * through it - a write made through the shared client instead would not
 * be rolled back with the entry. It returns the value for the caller plus
 * what to record: `detail`, and `entityId` when the record's key is only
 * known once it has been read (e.g. a grade's student and subject).
 *
 * Errors from `change` - Prisma's P2025 "not found", P2002 "already
 * exists", and so on - propagate unchanged, after the rollback, so route
 * handlers keep mapping them to 404/409 exactly as before.
 *
 * @template T
 * @param {object} db - The shared Prisma client (config/prisma.js).
 * @param {object} entry - Everything appendAuditEntry() needs except outcome and detail; statusCode defaults to 200.
 * @param {(tx: object) => Promise<{result: T, detail?: object, entityId?: string}>} change
 * @returns {Promise<T>} `result` from `change`.
 */
export async function withAudit(db, entry, change) {
    return db.$transaction(async (tx) => {
        const { result, detail = null, entityId } = await change(tx);
        await appendAuditEntry(tx, {
            ...entry,
            entityId: entityId ?? entry.entityId,
            outcome: "SUCCESS",
            statusCode: entry.statusCode ?? 200,
            detail
        });
        return result;
    });
}

/**
 * Records an entry on its own, best-effort - for refused and failed
 * attempts, which have no change to be atomic with, and for actions that
 * are not database writes (a snapshot download). Never throws: an audit
 * write failing here must not turn the administrator's 404 into a 500 or
 * break a download already sent. The failure is logged instead.
 *
 * @param {object} db - The shared Prisma client (config/prisma.js).
 * @param {object} entry - See appendAuditEntry().
 * @returns {Promise<void>}
 */
export async function recordAudit(db, entry) {
    try {
        await db.$transaction(tx => appendAuditEntry(tx, entry));
    } catch (err) {
        console.error(`[AUDIT] Could not record ${entry.action} on ${entry.entityType} ${entry.entityId}:`, err.message);
    }
}

/**
 * Decrypts an entry's stored `detail` for display. AES-GCM refuses to
 * decrypt bytes altered after encryption, so `readable: false` means the
 * ciphertext was tampered with (or written under a different key) - shown
 * as such, never as an empty change list.
 *
 * @param {string|null} stored - The `detail` column as stored.
 * @returns {{detail: object|null, readable: boolean}}
 */
export function readAuditDetail(stored) {
    if (stored == null) return { detail: null, readable: true };
    try {
        return { detail: JSON.parse(decryptField(stored)), readable: true };
    } catch {
        return { detail: null, readable: false };
    }
}

/**
 * Walks the whole chain, oldest entry first, and recomputes every seal -
 * see this file's @fileoverview for what each kind of failure means. Reads
 * in id-ordered batches, so memory use depends on the batch size, not on
 * how long the trail has grown.
 *
 * @param {object} db - The shared Prisma client (config/prisma.js).
 * @param {object} [options]
 * @param {number} [options.batchSize]
 * @param {Buffer} [options.key] - Defaults to the application's chain key; tests pass their own.
 * @returns {Promise<{intact: boolean, checked: number, headHash?: string|null, brokenAt?: number, reason?: string}>}
 *          `checked` counts the entries verified before any break.
 *          `headHash` is the newest seal, or null for an empty trail.
 */
export async function verifyAuditChain(db, { batchSize = 1000, key = chainKey() } = {}) {
    let expectedPrevHash = GENESIS_HASH;
    let checked = 0;
    let afterId = 0;

    for (;;) {
        const rows = await db.auditLog.findMany({ where: { id: { gt: afterId } }, orderBy: { id: "asc" }, take: batchSize });

        for (const row of rows) {
            if (row.prevHash !== expectedPrevHash) {
                return {
                    intact: false, checked, brokenAt: row.id,
                    reason: `Entry #${row.id} does not follow on from the entry before it: an entry was deleted, inserted or reordered at this point.`
                };
            }
            if (!sealsMatch(sealEntry(row, key), row.hash)) {
                return {
                    intact: false, checked, brokenAt: row.id,
                    reason: `Entry #${row.id} no longer matches its seal: it was changed after it was written.`
                };
            }
            expectedPrevHash = row.hash;
            checked++;
        }

        if (rows.length < batchSize) break;
        afterId = rows[rows.length - 1].id;
    }

    return { intact: true, checked, headHash: checked > 0 ? expectedPrevHash : null };
}
