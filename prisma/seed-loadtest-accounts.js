git add public/admin_dashboard.js public/admin_login.js public/script.jsimport bcrypt from 'bcryptjs';
import { writeFileSync, mkdirSync } from 'fs';
// Shared, encryption-extended singleton (config/prisma.js) - same reason
// prisma/seed.js and prisma/seed-bulk.js use it: nothing here writes an
// encrypted field, but User is a model the shared client already covers.
import prisma from '../config/prisma.js';

/**
 * Companion to prisma/seed-bulk.js, for Phase 3 (k6 load testing).
 *
 * prisma/seed-bulk.js only creates Student/Grade rows - no login (User)
 * accounts - because Phase 1 only asked for student records. But
 * loadtest/weva-defense-test.js's legitimate-user traffic is more
 * realistic as many distinct students than as every virtual user sharing
 * the one seeded demo account (its fallback when accounts.json is absent).
 *
 * Run this AFTER prisma/seed-bulk.js and AFTER pointing DATABASE_URL at
 * whichever environment you're about to load-test (local, or the AWS RDS
 * instance once Phase 2 is live). It links COUNT bulk-seeded students
 * (whichever currently have no login account) to a fresh User row, all
 * sharing one known password, and writes their emails to
 * loadtest/accounts.json for the k6 script to read.
 */
const COUNT = Number(process.env.LOADTEST_ACCOUNT_COUNT) || 1000;
const PASSWORD = process.env.LOADTEST_PASSWORD || 'LoadTest!2026';
const OUTPUT_DIR = new URL('../loadtest/', import.meta.url);
const OUTPUT_PATH = new URL('../loadtest/accounts.json', import.meta.url);

async function main() {
  const passwordHash = await bcrypt.hash(PASSWORD, 10);

  const candidates = await prisma.student.findMany({
    where: { userId: null },
    take: COUNT,
    select: { id: true, studentId: true },
  });

  if (candidates.length < COUNT) {
    console.warn(
      `Only ${candidates.length} unlinked students available (asked for ${COUNT}). ` +
      `Run prisma/seed-bulk.js with a higher SEED_COUNT first if you need more.`
    );
  }

  const emails = [];
  for (const student of candidates) {
    const email = `${student.studentId.toLowerCase()}@loadtest.example.edu.ph`;
    const user = await prisma.user.upsert({
      where: { email },
      update: { passwordHash, role: 'student' },
      create: { email, passwordHash, role: 'student' },
    });
    await prisma.student.update({ where: { id: student.id }, data: { userId: user.id } });
    emails.push(email);
  }

  mkdirSync(OUTPUT_DIR, { recursive: true });
  writeFileSync(OUTPUT_PATH, JSON.stringify({ password: PASSWORD, emails }, null, 2));
  console.log(`Linked ${emails.length} login accounts for load testing. Wrote loadtest/accounts.json.`);
}

main()
  .catch((err) => {
    console.error('Load-test account seed failed:', err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
