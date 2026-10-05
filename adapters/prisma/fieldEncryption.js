import { randomBytes, createCipheriv, createDecipheriv, hkdfSync } from "crypto";

/**
 * @fileoverview AES-256-GCM field-level encryption, applied transparently
 * via a Prisma Client Extension.
 *
 * This is deliberately an adapters/prisma/ concern, not a core/ one: it is
 * "how a value actually gets stored," the same category of decision as
 * PrismaIpTrackingStore choosing a Postgres table (see ipTrackingStore.js).
 * Nothing in core/, and nothing in the 20+ route handlers in server.js,
 * needs to know this exists - every caller keeps reading and writing plain
 * JS values (numbers, strings) exactly as before; only this file and the
 * database column in between ever see ciphertext. That is the whole reason
 * this is implemented as a Prisma $extends() query interceptor rather than
 * sprinkling encrypt()/decrypt() calls through server.js: the hexagonal
 * boundary this app already draws around storage (core/ports.js) stays
 * intact, and a field can be added to or removed from encryption by
 * editing ENCRYPTED_FIELDS below alone.
 *
 * config/prisma.js applies this extension once, to the one shared
 * PrismaClient singleton every other file in this app imports - so every
 * consumer is covered automatically, with no per-call-site opt-in.
 *
 * ---- Envelope format ----
 * Each encrypted column stores "<iv>:<authTag>:<ciphertext>", every segment
 * independently base64-encoded (base64's alphabet never contains ":", so
 * splitting on it is unambiguous). All three are required to decrypt:
 *
 *   - iv: 12 random bytes (crypto.randomBytes), freshly generated on every
 *     single encryption call. AES-GCM's confidentiality guarantee depends
 *     entirely on never reusing an (iv, key) pair - reuse leaks the XOR of
 *     the two plaintexts and can recover the authentication key outright.
 *     Generating a fresh IV per call, rather than per process or per row,
 *     is what makes that reuse structurally impossible here.
 *   - authTag: GCM's 16-byte authentication tag, produced by the cipher
 *     alongside the ciphertext. This is what makes GCM *authenticated*
 *     encryption rather than just encryption: decryptField() below feeds
 *     it back in via setAuthTag() before the final decrypt, and Node
 *     throws instead of returning plaintext if a single byte of the
 *     ciphertext (or the tag itself) was altered after encryption. A mode
 *     like AES-256-CBC would decrypt tampered ciphertext into silent
 *     garbage instead of raising an error - see fieldEncryption.test.js
 *     for a test that proves this property.
 *   - ciphertext: the encrypted value itself, always the UTF-8 bytes of
 *     String(plaintext) - so a numeric Grade.grade value like 1.25 is
 *     encrypted as the string "1.25" and comes back out the same way;
 *     Number(decrypted) at every existing calling site (e.g. server.js's
 *     /api/students/me) already handles that conversion.
 *
 * ---- Key ----
 * FIELD_ENCRYPTION_KEY (.env) is a 32-byte key, hex-encoded, distinct from
 * JWT_SECRET - a different secret for a different purpose, so a leak of
 * one never implicates the other. Generate one with:
 *
 *   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 *
 * Loaded once at import time and required to be present, mirroring the
 * JWT_SECRET check in server.js: fail loudly at startup if it is missing,
 * rather than mysteriously on the first write to an encrypted field.
 */

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH_BYTES = 12; // NIST SP 800-38D's recommended GCM nonce length

/**
 * @returns {Buffer} 32-byte key decoded from FIELD_ENCRYPTION_KEY.
 * @throws {Error} If the env var is missing or does not decode to 32 bytes.
 */
function loadKey() {
    const configured = process.env.FIELD_ENCRYPTION_KEY;
    if (!configured) {
        throw new Error(
            "FIELD_ENCRYPTION_KEY is not set. Add a 32-byte hex key to your .env file " +
            "(generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\")."
        );
    }

    const key = Buffer.from(configured, "hex");
    if (key.length !== 32) {
        throw new Error(`FIELD_ENCRYPTION_KEY must decode to exactly 32 bytes for AES-256 (got ${key.length}).`);
    }

    return key;
}

const KEY = loadKey();

/**
 * Derives a separate 32-byte key for another purpose from
 * FIELD_ENCRYPTION_KEY, with HKDF-SHA256 (RFC 5869), instead of reusing the
 * encryption key itself. Each `purpose` label yields an unrelated key, and
 * none of them reveals the master key or each other - so, for example, the
 * audit trail's HMAC key (utils/auditTrail.js) is independent of the key
 * that encrypts grades, with no second secret to configure and keep in sync
 * across Render and every local .env.
 *
 * @param {string} purpose - Fixed label naming what the key is for, e.g. "audit-chain-v1".
 * @returns {Buffer} 32-byte derived key.
 */
export function deriveKey(purpose) {
    return Buffer.from(hkdfSync("sha256", KEY, Buffer.alloc(0), `sis:${purpose}`, 32));
}

/**
 * Encrypts one value into the "iv:authTag:ciphertext" envelope described
 * above. `null`/`undefined` pass through unchanged, so an optional field
 * (e.g. Grade.grade before a score is entered) stays a real SQL NULL
 * instead of becoming "encrypted null" - preserving the column's existing
 * nullable semantics exactly.
 *
 * @param {*} plaintext - Value to encrypt; coerced to a string first.
 * @returns {string|null|undefined}
 */
export function encryptField(plaintext) {
    if (plaintext === null || plaintext === undefined) return plaintext;

    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv(ALGORITHM, KEY, iv);
    const ciphertext = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag(); // must be read after final()

    return [iv, authTag, ciphertext].map(buf => buf.toString("base64")).join(":");
}

/**
 * Decrypts one "iv:authTag:ciphertext" envelope back to the original
 * string. Throws if the envelope is malformed, or if the authTag does not
 * match the ciphertext - the latter means the stored bytes were altered
 * (accidental corruption or deliberate tampering) since they were
 * encrypted, and returning corrupted data silently would be worse than
 * refusing to decrypt it at all.
 *
 * @param {*} stored - Column value read back from the database.
 * @returns {string|null|undefined}
 */
export function decryptField(stored) {
    if (stored === null || stored === undefined) return stored;

    const parts = String(stored).split(":");
    if (parts.length !== 3) {
        throw new Error("Encrypted field is not a valid iv:authTag:ciphertext envelope - was it written before field encryption was enabled?");
    }

    const [iv, authTag, ciphertext] = parts.map(part => Buffer.from(part, "base64"));
    const decipher = createDecipheriv(ALGORITHM, KEY, iv);
    decipher.setAuthTag(authTag); // must be set before final()

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

/**
 * Models, and the fields on each, that should be transparently encrypted
 * at rest. Keyed by the PascalCase model name exactly as it appears in
 * prisma/schema.prisma (confirmed empirically against this project's
 * generated client - Prisma's extension API passes this, not the
 * camelCase `prisma.grade` client property name).
 *
 * To encrypt another field later (e.g. Student.fullName), add one line
 * here - nothing else in this file, or in any consumer, changes:
 *
 *   Student: ["fullName"],
 */
const ENCRYPTED_FIELDS = {
    Grade: ["grade"]
};

/**
 * Encrypts every configured field present in a write operation's payload,
 * in place. Only touches keys that already exist on the object (via
 * hasOwnProperty), so Prisma's partial-update semantics are preserved
 * exactly - a field genuinely omitted from a PUT body must stay omitted,
 * not become an explicit `undefined` write.
 *
 * Skips a value that is already a non-null object (e.g. a nested
 * `{ set: ... }` or `{ increment: ... }` write) rather than encrypting
 * "[object Object]" - none of today's ENCRYPTED_FIELDS need those, but a
 * future encrypted numeric field might, and this keeps that failure mode
 * loud (a decrypt error later) instead of silent data corruption now.
 *
 * @param {string[]} fields
 * @param {object|null|undefined} data
 * @returns {void}
 */
function encryptInPlace(fields, data) {
    if (!data || typeof data !== "object") return;

    for (const field of fields) {
        if (!Object.prototype.hasOwnProperty.call(data, field)) continue;
        const value = data[field];
        if (value !== null && typeof value === "object") continue;
        data[field] = encryptField(value);
    }
}

/**
 * Routes encryption to wherever a write operation's payload actually
 * lives - `args.data` covers create/update/updateMany, `args.data[]`
 * covers createMany, and upsert splits across `args.create`/`args.update`.
 *
 * @param {string[]} fields
 * @param {string} operation - Prisma operation name (e.g. "create").
 * @param {object} args
 * @returns {void}
 */
function encryptArgs(fields, operation, args) {
    if (!args) return;

    if (operation === "createMany" && Array.isArray(args.data)) {
        args.data.forEach(row => encryptInPlace(fields, row));
    } else if (operation === "upsert") {
        encryptInPlace(fields, args.create);
        encryptInPlace(fields, args.update);
    } else if (args.data) {
        encryptInPlace(fields, args.data);
    }
}

/**
 * Decrypts every configured field present on a single result row, in
 * place. `!= null` (not `!==`) deliberately catches both null and
 * undefined, so a row with no grade yet is never handed to decryptField().
 *
 * @param {string[]} fields
 * @param {object} row
 * @returns {object}
 */
function decryptRow(fields, row) {
    if (!row || typeof row !== "object") return row;

    for (const field of fields) {
        if (Object.prototype.hasOwnProperty.call(row, field) && row[field] != null) {
            row[field] = decryptField(row[field]);
        }
    }
    return row;
}

/**
 * Decrypts a query's result, whatever shape it comes back in: a single row
 * (findUnique/findFirst/create/update/delete/upsert), an array of rows
 * (findMany), or a primitive (count() returns a number - nothing to
 * decrypt, passed through untouched).
 *
 * @param {string[]} fields
 * @param {*} result
 * @returns {*}
 */
function decryptResult(fields, result) {
    if (result == null) return result;
    if (Array.isArray(result)) return result.map(row => decryptRow(fields, row));
    if (typeof result === "object") return decryptRow(fields, result);
    return result;
}

/**
 * The Prisma Client Extension itself - see config/prisma.js for where it
 * is applied to the shared singleton. A single $allModels/$allOperations
 * interceptor, rather than one entry per model, so adding a newly
 * encrypted model is a one-line change to ENCRYPTED_FIELDS above and
 * nothing more; a model with no entry there is a guaranteed no-op pass
 * through query(args), so this extension is invisible to every other
 * model already served by this app's PrismaClient (User, Session,
 * BehaviorLog, IpTracking, ...).
 *
 * Note for anyone tempted to `where: { grade: ... }`, sort by grade, or
 * `_avg`/`_sum` it: don't. Each ciphertext is unique even for the same
 * plaintext (fresh IV per call - see encryptField()), so equality,
 * ordering, and aggregation on an encrypted column are all meaningless at
 * the database level. Filter/sort in application code on the decrypted
 * value after fetching instead, the same way server.js already computes
 * GWA in JS from fetched rows rather than a SQL AVG().
 */
export const fieldEncryptionExtension = {
    name: "field-encryption",
    query: {
        $allModels: {
            async $allOperations({ model, operation, args, query }) {
                const fields = ENCRYPTED_FIELDS[model];
                if (!fields) return query(args);

                encryptArgs(fields, operation, args);
                const result = await query(args);
                return decryptResult(fields, result);
            }
        }
    }
};
