import 'dotenv/config';
import { describe, it, expect } from 'vitest';
import { encryptField, decryptField } from './fieldEncryption.js';

/**
 * @fileoverview Proves the AES-256-GCM envelope in fieldEncryption.js
 * round-trips correctly, never reuses an IV, and - the property that
 * actually justifies choosing GCM over a non-authenticated mode like
 * AES-256-CBC - rejects ciphertext that has been tampered with after
 * encryption, rather than silently decrypting it into garbage. No
 * database involved: these are pure functions over strings, in the same
 * spirit as core/mitigation.test.js's fake-store approach.
 *
 * Requires FIELD_ENCRYPTION_KEY to be set (see .env) - the explicit
 * `import 'dotenv/config'` above loads it when vitest runs this file
 * directly, the same way server.js loads it for the real app.
 */

describe('encryptField / decryptField', () => {
    it('round-trips a plaintext value unchanged', () => {
        const encrypted = encryptField('1.25');
        expect(encrypted).not.toBe('1.25');
        expect(decryptField(encrypted)).toBe('1.25');
    });

    it('coerces a numeric value to its string form on the way in', () => {
        const encrypted = encryptField(1.25);
        expect(decryptField(encrypted)).toBe('1.25');
    });

    it('passes null and undefined through unchanged, on both sides', () => {
        expect(encryptField(null)).toBeNull();
        expect(encryptField(undefined)).toBeUndefined();
        expect(decryptField(null)).toBeNull();
        expect(decryptField(undefined)).toBeUndefined();
    });

    it('never reuses an IV, even for the identical plaintext twice in a row', () => {
        const first = encryptField('1.25');
        const second = encryptField('1.25');

        expect(first).not.toBe(second); // different IV -> different envelope
        expect(decryptField(first)).toBe('1.25');
        expect(decryptField(second)).toBe('1.25'); // both still decrypt correctly
    });

    it('rejects an envelope whose ciphertext was tampered with after encryption', () => {
        const encrypted = encryptField('1.25');
        const [iv, authTag, ciphertext] = encrypted.split(':');

        // Flip the ciphertext's first base64 character - simulates a byte
        // being altered in the database, whether by corruption or by
        // deliberate tampering.
        const flipped = (ciphertext[0] === 'A' ? 'B' : 'A') + ciphertext.slice(1);
        const tampered = [iv, authTag, flipped].join(':');

        expect(() => decryptField(tampered)).toThrow();
    });

    it('rejects a value that is not a valid iv:authTag:ciphertext envelope', () => {
        // e.g. a pre-encryption plaintext row that was never migrated.
        expect(() => decryptField('1.25')).toThrow();
    });
});
