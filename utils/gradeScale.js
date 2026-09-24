/**
 * @fileoverview Input validation for grade records (POST/PUT /api/grades in
 * server.js).
 *
 * Why the application has to do this: Grade.grade is encrypted at rest
 * (adapters/prisma/fieldEncryption.js), so the column is now a VARCHAR
 * holding an AES-GCM envelope. It used to be DECIMAL(3,2), and the database
 * itself refused a value like 999 or "abc". Ciphertext has no type or
 * range the database can check, so without validation here, any string was
 * accepted, encrypted and stored - and "abc" then decrypted into a grade of
 * NaN, turning the student's GWA into NaN.
 */

/**
 * Every grade the Philippine collegiate scale allows: 1.00 (highest)
 * through 3.00 (lowest passing) in 0.25 steps, 4.00 (conditional failure,
 * used by some institutions) and 5.00 (failure). An incomplete or dropped
 * subject has no grade at all: `null`, with the reason in `remarks`
 * (e.g. "INC").
 */
export const GRADE_SCALE = Object.freeze(['1.00', '1.25', '1.50', '1.75', '2.00', '2.25', '2.50', '2.75', '3.00', '4.00', '5.00']);

/** Column width of Grade.term and Grade.remarks (VARCHAR(50) in prisma/schema.prisma). */
const TEXT_MAX_LENGTH = 50;

/**
 * Validates a grade and returns it in the one canonical form it is stored
 * in: a two-decimal string ("1.5" and 1.5 both become "1.50"), so every
 * encrypted grade decrypts to the same text the rest of the app expects.
 *
 * `undefined` means "not provided" (a PUT that leaves the grade alone) and
 * `null` means "no grade" (incomplete/dropped); both pass through unchanged.
 *
 * @param {*} input - Raw value from the request body.
 * @returns {{ok: true, value: string|null|undefined} | {ok: false}}
 */
export function parseGrade(input) {
    if (input === undefined || input === null) return { ok: true, value: input };
    if (typeof input !== 'number' && typeof input !== 'string') return { ok: false };

    const text = String(input).trim();
    if (!/^\d(\.\d{1,2})?$/.test(text)) return { ok: false };

    const canonical = Number(text).toFixed(2);
    return GRADE_SCALE.includes(canonical) ? { ok: true, value: canonical } : { ok: false };
}

/**
 * Validates an optional short text field (Grade.term, Grade.remarks):
 * trimmed, at most 50 characters. `undefined` means "not provided";
 * `null` or an empty string clears the field.
 *
 * @param {*} input - Raw value from the request body.
 * @returns {{ok: true, value: string|null|undefined} | {ok: false}}
 */
export function parseShortText(input) {
    if (input === undefined) return { ok: true, value: undefined };
    if (input === null) return { ok: true, value: null };
    if (typeof input !== 'string') return { ok: false };

    const text = input.trim();
    if (text.length > TEXT_MAX_LENGTH) return { ok: false };
    return { ok: true, value: text === '' ? null : text };
}
