import { describe, it, expect } from 'vitest';
import { GRADE_SCALE, parseGrade, parseShortText } from './gradeScale.js';

describe('parseGrade', () => {
    it('accepts every grade on the scale, as a string or a number, in canonical two-decimal form', () => {
        for (const grade of GRADE_SCALE) {
            expect(parseGrade(grade)).toEqual({ ok: true, value: grade });
            expect(parseGrade(Number(grade))).toEqual({ ok: true, value: grade });
        }
        expect(parseGrade('1.5')).toEqual({ ok: true, value: '1.50' });
        expect(parseGrade(' 3 ')).toEqual({ ok: true, value: '3.00' });
    });

    it('passes "not provided" (undefined) and "no grade" (null) through', () => {
        expect(parseGrade(undefined)).toEqual({ ok: true, value: undefined });
        expect(parseGrade(null)).toEqual({ ok: true, value: null });
    });

    it('rejects anything off the scale - the values the encrypted column can no longer refuse on its own', () => {
        for (const bad of ['999', 999, 'abc', '', '3.25', '3.5', '4.5', '0', 0, 6, '-1', '1.255', 'NaN', NaN, Infinity, '1e0', {}, [], true]) {
            expect(parseGrade(bad), `should reject ${JSON.stringify(bad)}`).toEqual({ ok: false });
        }
    });
});

describe('parseShortText', () => {
    it('trims text, maps empty to null, and passes undefined through', () => {
        expect(parseShortText('  INC  ')).toEqual({ ok: true, value: 'INC' });
        expect(parseShortText('')).toEqual({ ok: true, value: null });
        expect(parseShortText(null)).toEqual({ ok: true, value: null });
        expect(parseShortText(undefined)).toEqual({ ok: true, value: undefined });
    });

    it('rejects non-strings and anything longer than the 50-character column', () => {
        expect(parseShortText('x'.repeat(51))).toEqual({ ok: false });
        expect(parseShortText(42)).toEqual({ ok: false });
        expect(parseShortText({ contains: 'x' })).toEqual({ ok: false });
    });
});
