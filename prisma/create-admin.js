import bcrypt from 'bcryptjs';
// Shared, encryption-extended singleton (config/prisma.js), same as the seed scripts.
import prisma from '../config/prisma.js';

// Admin login emails its OTP to the account's own address, so the demo
// admin@example.edu.ph can never finish logging in. This creates (or resets)
// an admin whose email is an inbox you can actually read:
//   ADMIN_EMAIL=you@gmail.com ADMIN_PASSWORD='...' node prisma/create-admin.js
const { ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;

if (!ADMIN_EMAIL || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 8 characters).');
  process.exit(1);
}

try {
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  const admin = await prisma.user.upsert({
    where: { email: ADMIN_EMAIL },
    update: { passwordHash, role: 'admin' },
    create: { email: ADMIN_EMAIL, passwordHash, role: 'admin' },
  });
  console.log(`Admin ready: ${admin.email} (id ${admin.id}).`);
} finally {
  await prisma.$disconnect();
}
