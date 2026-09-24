/**
 * @fileoverview Grade report math shared by the student's own dashboard
 * (GET /api/students/me) and the admin's grade lookup
 * (GET /api/students/:id/grades) in server.js, so the two can never
 * disagree. Kept out of server.js so it can be unit-tested
 * (gradeSummary.test.js) without starting the HTTP server.
 */

/** Philippine 1.00 (highest) - 5.00 (lowest) scale: 3.00 is the passing ceiling for "Good Standing". */
const GOOD_STANDING_MAX_GWA = 3.00;

/**
 * Shapes grade rows (each with its subject included) for display, and
 * derives enrolled units, GWA and academic standing from them.
 *
 * GWA is the General *Weighted* Average: every grade counts in proportion
 * to its subject's units, not once per subject.
 *
 *     GWA = sum(grade x units) / sum(units)     (graded subjects only)
 *
 * Worked example - 1.00 in a 5-unit subject and 3.00 in a 1-unit subject:
 *     (1.00 x 5 + 3.00 x 1) / (5 + 1) = 8 / 6 = 1.33
 * A plain mean of the two grades would report 2.00, overstating the weight
 * of the 1-unit subject five times over.
 *
 * Rows without a numeric grade (not yet encoded, or INC) are left out of
 * both sums, so they neither pull the average toward 0 nor dilute it. They
 * still count toward enrolledUnits, since the student is still carrying
 * those units.
 *
 * Enrolled units and GWA are computed from the real grade rows rather than
 * stored as separate fields, so they can never drift out of sync with the
 * grades that back them. The Philippine scale runs 1.00 (highest) to 5.00
 * (lowest), so the average is taken directly (no inversion).
 *
 * @param {Array<object>} gradeRows - Grade rows fetched with `include: { subject: true }`. `grade` arrives as the decrypted string from adapters/prisma/fieldEncryption.js (e.g. "1.25") or null.
 * @returns {{grades: Array<object>, stats: {enrolledUnits: number, gwa: number|null, academicStanding: string}}}
 */
export function summarizeGrades(gradeRows) {
    const grades = gradeRows.map(g => ({
        subjectCode: g.subject.subjectCode,
        subjectTitle: g.subject.subjectTitle,
        units: g.subject.units,
        term: g.term,
        grade: g.grade != null ? Number(g.grade) : null,
        remarks: g.remarks
    }));

    const enrolledUnits = grades.reduce((sum, g) => sum + (g.units || 0), 0);

    const graded = grades.filter(g => Number.isFinite(g.grade) && g.units > 0);
    const gradedUnits = graded.reduce((sum, g) => sum + g.units, 0);
    const weightedSum = graded.reduce((sum, g) => sum + g.grade * g.units, 0);
    // Number.EPSILON keeps a true x.xx5 from rounding down because of
    // binary floating point (e.g. 1.005 * 100 === 100.49999999999999).
    const gwa = gradedUnits > 0
        ? Math.round((weightedSum / gradedUnits + Number.EPSILON) * 100) / 100
        : null;

    const academicStanding = gwa == null
        ? 'No Grades Yet'
        : (gwa <= GOOD_STANDING_MAX_GWA ? 'Good Standing' : 'On Probation');

    return { grades, stats: { enrolledUnits, gwa, academicStanding } };
}
