// Shared, encryption-extended singleton (config/prisma.js), same as the seed scripts.
import prisma from '../config/prisma.js';

// Break-glass unblock for an operator locked out of the admin dashboard's Blocked
// Devices panel: clears every active WEVA / IP-whitelist block record. It needs the
// database credentials, so only someone who already controls the system can use it:
//   DATABASE_URL="<rds url>" node prisma/clear-blocks.js
// WEVA's in-memory history (per-device attempt counts, per-IP 30 s windows) lives
// in the server process, so restart the Render service as well.
try {
  const { count } = await prisma.ipTracking.updateMany({
    where: { isBlocked: true },
    data: { isBlocked: false, blockedUntil: null },
  });
  console.log(`Cleared ${count} block record(s).`);
} finally {
  await prisma.$disconnect();
}
