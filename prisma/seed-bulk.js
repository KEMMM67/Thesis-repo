import { faker } from '@faker-js/faker';
// Shared, encryption-extended singleton (config/prisma.js), same as
// prisma/seed.js - a fresh `new PrismaClient()` here would write
// Grade.grade as plaintext, silently bypassing
// adapters/prisma/fieldEncryption.js entirely.
import prisma from '../config/prisma.js';

// Override with `SEED_COUNT=50 node prisma/seed-bulk.js` for a fast local
// smoke test before committing to the full 15,000-row run.
const TOTAL_STUDENTS = Number(process.env.SEED_COUNT) || 15000;
const BATCH_SIZE = 1000;

// Postgres caps a single query at 65535 bind parameters. Each batch's
// student insert uses 6 params/row and its grade insert 5 params/row x up
// to 3 subjects/student, so BATCH_SIZE=1000 (6,000 and up to 15,000 params
// respectively) stays far under that ceiling while keeping each
// createMany/findMany round trip - and the array it holds - small enough
// that memory use never grows with TOTAL_STUDENTS.
if (BATCH_SIZE * 3 * 5 > 65535) {
  throw new Error('BATCH_SIZE too large for a single grade createMany() call.');
}

const DEPARTMENTS = [
  { code: 'CCMS', programs: ['BSCS - SoftEng', 'BSCS - Networking', 'BS Info Tech'] },
  { code: 'CAS', programs: ['BS Psychology', 'BS Biology', 'AB Communication'] },
  { code: 'CENG', programs: ['BS Civil Eng', 'BS Electrical Eng', 'BS Mechanical Eng'] },
  { code: 'CIHTM', programs: ['BS Tourism', 'BS Hospitality Mgmt'] },
  { code: 'CCJS', programs: ['BS Criminology'] },
  { code: 'CNAHS', programs: ['BS Nursing', 'BS Midwifery'] },
  { code: 'CED', programs: ['BSEd Mathematics', 'BSEd English', 'BEEd'] },
];

// Weighted pools (plain arrays, sampled uniformly) instead of a percentage
// table, so the shape of a realistic cohort - mostly enrolled, a handful
// irregular, fewer dropped - is visible directly in the data below rather
// than in separate probability numbers.
const STATUS_POOL = [...Array(90).fill('ENROLLED'), ...Array(7).fill('IRREGULAR'), ...Array(3).fill('DROPPED')];

const YEAR_LEVELS = [
  { label: '1st Year', enrollOffset: 0 },
  { label: '2nd Year', enrollOffset: 1 },
  { label: '3rd Year', enrollOffset: 2 },
  { label: '4th Year', enrollOffset: 3 },
];

// Matches prisma/seed.js's GRADE_SEED term string, so bulk-seeded and demo
// grades sit in the same academic term.
const TERM = '1st Semester, 2025-2026';
const CURRENT_ENROLL_YEAR = 2025;

const SUBJECT_SEED = [
  { subjectCode: 'SE301', subjectTitle: 'Software Engineering 1', units: 3, department: 'CCMS' },
  { subjectCode: 'IAS301', subjectTitle: 'Information Assurance and Security', units: 3, department: 'CCMS' },
  { subjectCode: 'HCI101', subjectTitle: 'Human-Computer Interaction', units: 3, department: 'CCMS' },
];

// Philippine collegiate grading scale (1.00 best - 5.00 fail, 0.25
// increments). Weighted toward the 1.75-2.75 band instead of a flat
// uniform draw, so a GWA computed from this data looks like a real
// cohort's rather than statistically flat noise. Kept as pre-formatted
// strings, not numbers: encryptField() (adapters/prisma/fieldEncryption.js)
// coerces its input with String(), and JS's own number->string conversion
// drops trailing zeros (String(1.00) === "1") - encrypting the exact
// display string here is what keeps a whole-number grade encrypted (and
// later decrypted) as "1.00" instead of "1".
const GRADE_POOL = [
  ...Array(4).fill('1.00'), ...Array(6).fill('1.25'), ...Array(10).fill('1.50'),
  ...Array(14).fill('1.75'), ...Array(16).fill('2.00'), ...Array(14).fill('2.25'),
  ...Array(12).fill('2.50'), ...Array(10).fill('2.75'), ...Array(8).fill('3.00'),
  ...Array(6).fill('5.00'),
];

function pick(pool) {
  return pool[Math.floor(Math.random() * pool.length)];
}

function remarksFor(grade) {
  return grade === '5.00' ? 'Failed' : 'Passed';
}

async function upsertSubjects() {
  const subjects = await Promise.all(
    SUBJECT_SEED.map((s) => prisma.subject.upsert({ where: { subjectCode: s.subjectCode }, update: s, create: s }))
  );
  console.log(`Subjects ready: ${subjects.map((s) => s.subjectCode).join(', ')}`);
  return subjects;
}

/**
 * Builds one student row. `seq` (1..TOTAL_STUDENTS, globally unique) is
 * embedded in studentId, so uniqueness holds regardless of how many other
 * students happen to share the same department/enrollment-year prefix.
 */
function buildStudent(seq) {
  const dept = pick(DEPARTMENTS);
  const program = pick(dept.programs);
  const yearLevel = pick(YEAR_LEVELS);
  const enrollYear = CURRENT_ENROLL_YEAR - yearLevel.enrollOffset;
  const studentId = `${dept.code.slice(0, 2)}${String(enrollYear).slice(-2)}-${String(seq).padStart(6, '0')}`;

  return {
    studentId,
    fullName: `${faker.person.lastName().toUpperCase()}, ${faker.person.firstName().toUpperCase()}`,
    department: dept.code,
    program,
    yearLevel: yearLevel.label,
    status: pick(STATUS_POOL),
  };
}

async function main() {
  console.log(`Bulk-seeding ${TOTAL_STUDENTS} students in batches of ${BATCH_SIZE}...`);
  const subjects = await upsertSubjects();
  const start = Date.now();

  let studentsCreated = 0;
  let gradesCreated = 0;

  for (let batchStart = 1; batchStart <= TOTAL_STUDENTS; batchStart += BATCH_SIZE) {
    const batchEnd = Math.min(batchStart + BATCH_SIZE - 1, TOTAL_STUDENTS);
    const batch = [];
    for (let seq = batchStart; seq <= batchEnd; seq++) batch.push(buildStudent(seq));

    // 1) Insert this chunk only - skipDuplicates makes a re-run idempotent
    //    (existing rows are left alone instead of crashing on the unique
    //    studentId constraint) if the script is interrupted and restarted.
    const { count: insertedCount } = await prisma.student.createMany({ data: batch, skipDuplicates: true });
    studentsCreated += insertedCount;

    // 2) createMany() doesn't return the created rows or their
    //    autoincrement ids, and Grade needs the real integer studentId FK -
    //    so read this chunk back by its unique studentId. Bounded to
    //    BATCH_SIZE rows, so this never grows with TOTAL_STUDENTS.
    const insertedStudents = await prisma.student.findMany({
      where: { studentId: { in: batch.map((s) => s.studentId) } },
      select: { id: true, studentId: true },
    });

    // 3) One grade per subject per student in this chunk. `grade` is
    //    encrypted transparently here by fieldEncryptionExtension's
    //    createMany interceptor (adapters/prisma/fieldEncryption.js) via
    //    the shared `prisma` singleton imported above - identical to how
    //    prisma/seed.js's 3 demo grade rows are written, just at 15,000x
    //    the volume and via createMany's args.data[] path instead of a
    //    single create()'s args.data.
    const gradeRows = [];
    for (const student of insertedStudents) {
      for (const subject of subjects) {
        const grade = pick(GRADE_POOL);
        gradeRows.push({ studentId: student.id, subjectId: subject.id, term: TERM, grade, remarks: remarksFor(grade) });
      }
    }
    const { count: insertedGrades } = await prisma.grade.createMany({ data: gradeRows, skipDuplicates: true });
    gradesCreated += insertedGrades;

    const elapsedSec = ((Date.now() - start) / 1000).toFixed(1);
    console.log(
      `  batch ${batchStart}-${batchEnd}: +${insertedCount} students, +${insertedGrades} grades ` +
      `(${studentsCreated}/${TOTAL_STUDENTS} total, ${elapsedSec}s elapsed)`
    );
  }

  console.log(`Done: ${studentsCreated} students, ${gradesCreated} grades in ${((Date.now() - start) / 1000).toFixed(1)}s.`);
}

main()
  .catch((err) => {
    console.error('Bulk seed failed:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
