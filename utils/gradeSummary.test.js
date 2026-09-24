import { describe, it, expect } from 'vitest';
import { summarizeGrades } from './gradeSummary.js';

/** A grade row shaped like prisma.grade.findMany({ include: { subject: true } }) after decryption. */
function row(subjectCode, units, grade, remarks = 'Passed') {
    return { subject: { subjectCode, subjectTitle: `${subjectCode} title`, units }, term: '1st Semester, 2025-2026', grade, remarks };
}

describe('summarizeGrades', () => {
    it('weights each grade by its subject units (the documented 1.33 example)', () => {
        const { stats } = summarizeGrades([row('CAP401', 5, '1.00'), row('PE101', 1, '3.00')]);
        // A plain mean would be 2.00.
        expect(stats.gwa).toBe(1.33);
        expect(stats.enrolledUnits).toBe(6);
    });

    it('matches the plain mean when every subject carries the same units', () => {
        const { stats } = summarizeGrades([row('SE301', 3, '1.25'), row('IAS301', 3, '1.00'), row('HCI101', 3, '1.50')]);
        expect(stats.gwa).toBe(1.25);
        expect(stats.academicStanding).toBe('Good Standing');
    });

    it('leaves ungraded and non-numeric rows out of the GWA but keeps their units enrolled', () => {
        const { stats, grades } = summarizeGrades([
            row('SE301', 3, '2.00'),
            row('IAS301', 3, null, null),
            row('HCI101', 3, 'not-a-grade')
        ]);
        expect(stats.gwa).toBe(2.00);
        expect(stats.enrolledUnits).toBe(9);
        expect(grades[1].grade).toBeNull();
    });

    it('treats a GWA of exactly 3.00 as Good Standing and anything above as On Probation', () => {
        expect(summarizeGrades([row('A101', 3, '5.00', 'Failed'), row('B101', 3, '1.00')]).stats)
            .toMatchObject({ gwa: 3.00, academicStanding: 'Good Standing' });
        expect(summarizeGrades([row('A101', 3, '5.00', 'Failed'), row('B101', 2, '1.00')]).stats)
            .toMatchObject({ gwa: 3.4, academicStanding: 'On Probation' });
    });

    it('reports no GWA when nothing has been graded yet', () => {
        expect(summarizeGrades([]).stats).toEqual({ enrolledUnits: 0, gwa: null, academicStanding: 'No Grades Yet' });
    });

    it('rounds to 2 decimals, taking a true half-hundredth up despite floating point', () => {
        // (1.25 x 3 + 1.00 x 5) / 8 = 8.75 / 8 = 1.09375 -> 1.09
        expect(summarizeGrades([row('A101', 3, '1.25'), row('B101', 5, '1.00')]).stats.gwa).toBe(1.09);

        // A cumulative record: 49 subjects at 1.00 and one at 1.25, 3 units each.
        // (147 + 3.75) / 150 = 1.005 exactly, but 150.75 / 150 in binary floating
        // point is 1.00499999..., which plain Math.round(x * 100) takes down to 1.00.
        const record = Array.from({ length: 49 }, (_, i) => row(`S${i}`, 3, '1.00'));
        record.push(row('S49', 3, '1.25'));
        expect(summarizeGrades(record).stats.gwa).toBe(1.01);
    });
});
