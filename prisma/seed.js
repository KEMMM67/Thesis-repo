import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();
const SALT_ROUNDS = 10;

async function upsertTestUser(email, plainPassword, role) {
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);

  return prisma.user.upsert({
    where: { email },
    update: { passwordHash, role },
    create: { email, passwordHash, role },
  });
}

async function main() {
  const admin = await upsertTestUser('admin@example.edu.ph', 'admin123', 'admin');
  const student = await upsertTestUser('student@example.edu.ph', 'student123', 'student');

  console.log(`Seeded users: ${admin.email} (${admin.role}), ${student.email} (${student.role})`);

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