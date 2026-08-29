import { PrismaClient } from '@prisma/client';

// A single shared instance to avoid connection pool exhaustion
const prisma = new PrismaClient();

export default prisma;