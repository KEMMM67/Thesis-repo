import bcrypt from 'bcryptjs';
// Shared, encryption-extended singleton (config/prisma.js) - not a fresh
// `new PrismaClient()` of its own. A second, unextended instance would
// write Grade.grade as plaintext, silently bypassing
// adapters/prisma/fieldEncryption.js entirely.
import prisma from '../config/prisma.js';

const SALT_ROUNDS = 10;

async function upsertTestUser(email, plainPassword, role) {
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);

  return prisma.user.upsert({
    where: { email },
    update: { passwordHash, role },
    create: { email, passwordHash, role },
  });
}

// Same rows the admin dashboard used to hardcode as static <tr>
// markup (public/admin_dashboard.html, before Priority: "Modern UI
// Modals" replaced it with a real GET /api/students-backed table) -
// upserted here so the migration to real persistence doesn't look like
// data loss on first load.
const STUDENT_SEED = [
  { studentId: 'A23-00001', fullName: 'LAWAN, KHYNNE MARK ELMER', department: 'CCMS', program: 'BSCS - SoftEng', yearLevel: '3rd Year', status: 'ENROLLED' },
  { studentId: 'A23-00002', fullName: 'DELEÑA, KENJIE', department: 'CCMS', program: 'BSCS - SoftEng', yearLevel: '3rd Year', status: 'ENROLLED' },
  { studentId: 'A23-00003', fullName: 'LABSO, JOHN ELON', department: 'CCMS', program: 'BSCS - SoftEng', yearLevel: '3rd Year', status: 'ENROLLED' },
  { studentId: 'B24-10521', fullName: 'MENDOZA, MARIA CLARA', department: 'CAS', program: 'BS Psychology', yearLevel: '2nd Year', status: 'ENROLLED' },
  { studentId: 'C22-44122', fullName: 'SANTOS, JUAN DELA CRUZ', department: 'CENG', program: 'BS Civil Eng', yearLevel: '4th Year', status: 'IRREGULAR' },
  { studentId: 'D25-99211', fullName: 'REYES, ANA MARIE', department: 'CIHTM', program: 'BS Tourism', yearLevel: '1st Year', status: 'ENROLLED' },
  { studentId: 'E23-33291', fullName: 'GARCIA, MARK ANTHONY', department: 'CCJS', program: 'BS Criminology', yearLevel: '3rd Year', status: 'ENROLLED' },
  { studentId: 'F24-88124', fullName: 'FLORES, SAMANTHA', department: 'CNAHS', program: 'BS Nursing', yearLevel: '2nd Year', status: 'ENROLLED' },
  { studentId: 'G22-77451', fullName: 'CRUZ, JOSHUA', department: 'CED', program: 'BSEd Mathematics', yearLevel: '4th Year', status: 'ENROLLED' },
  { studentId: 'H25-11094', fullName: 'BAUTISTA, CHLOE', department: 'CCMS', program: 'BS Info Tech', yearLevel: '1st Year', status: 'DROPPED' },
];

const SUBJECT_SEED = [
  { subjectCode: 'SE301', subjectTitle: 'Software Engineering 1', units: 3, department: 'CCMS' },
  { subjectCode: 'IAS301', subjectTitle: 'Information Assurance and Security', units: 3, department: 'CCMS' },
  { subjectCode: 'HCI101', subjectTitle: 'Human-Computer Interaction', units: 3, department: 'CCMS' },
];

// Matches the grades student_dashboard.html's Grades Evaluation section
// used to hardcode for the same student.
const GRADE_SEED = [
  { studentId: 'A23-00001', subjectCode: 'SE301', term: '1st Semester, 2025-2026', grade: 1.25, remarks: 'Passed' },
  { studentId: 'A23-00001', subjectCode: 'IAS301', term: '1st Semester, 2025-2026', grade: 1.00, remarks: 'Passed' },
  { studentId: 'A23-00001', subjectCode: 'HCI101', term: '1st Semester, 2025-2026', grade: 1.50, remarks: 'Passed' },
];

/**
 * Upserts the demo academic records and links the demo student portal
 * account to its matching Student row via Student.userId, so
 * GET /api/students/me (server.js) has a real record to resolve for the
 * seeded student@example.edu.ph login.
 *
 * @param {number} demoStudentUserId - id of the seeded student@example.edu.ph User row.
 * @returns {Promise<void>}
 */
async function seedAcademicRecords(demoStudentUserId) {
  const students = await Promise.all(
    STUDENT_SEED.map((s) => {
      const data = s.studentId === 'A23-00001' ? { ...s, userId: demoStudentUserId } : s;
      return prisma.student.upsert({ where: { studentId: s.studentId }, update: data, create: data });
    })
  );
  const subjects = await Promise.all(
    SUBJECT_SEED.map((s) => prisma.subject.upsert({ where: { subjectCode: s.subjectCode }, update: s, create: s }))
  );

  const studentByCode = Object.fromEntries(students.map((s) => [s.studentId, s]));
  const subjectByCode = Object.fromEntries(subjects.map((s) => [s.subjectCode, s]));

  for (const g of GRADE_SEED) {
    const student = studentByCode[g.studentId];
    const subject = subjectByCode[g.subjectCode];
    await prisma.grade.upsert({
      where: { studentId_subjectId_term: { studentId: student.id, subjectId: subject.id, term: g.term } },
      update: { grade: g.grade, remarks: g.remarks },
      create: { studentId: student.id, subjectId: subject.id, term: g.term, grade: g.grade, remarks: g.remarks },
    });
  }

  console.log(`Seeded ${students.length} students, ${subjects.length} subjects, ${GRADE_SEED.length} grades.`);
}

async function main() {
  const admin = await upsertTestUser('admin@example.edu.ph', 'admin123', 'admin');
  const student = await upsertTestUser('student@example.edu.ph', 'student123', 'student');

  console.log(`Seeded users: ${admin.email} (${admin.role}), ${student.email} (${student.role})`);

  await seedAcademicRecords(student.id);

  await prisma.loginAttempt.createMany({
    data: [
      { userEmail: admin.email, userId: admin.id, ipAddress: '127.0.0.1', status: 'SUCCESS' },
      { userEmail: student.email, userId: student.id, ipAddress: '127.0.0.1', status: 'SUCCESS' },
    ],
  });

  await prisma.behaviorLog.createMany({
    data: [
      { userEmail: admin.email, userId: admin.id, eventType: 'LOGIN_SUCCESS', description: 'User logged in successfully.' },
      { userEmail: student.email, userId: student.id, eventType: 'LOGIN_SUCCESS', description: 'User logged in successfully.' },
    ],
  });

  await prisma.anomalyScore.create({
    data: { userEmail: student.email, userId: student.id, score: 4.5, riskLevel: 'LOW' },
  });

  await prisma.securityAction.create({
    data: {
      userEmail: student.email,
      userId: student.id,
      actionTaken: 'ALLOW',
      reason: 'Baseline behavior within normal range.',
    },
  });

  console.log('Seed complete.');
}

main()
  .catch((err) => {
    console.error('Seed failed:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });