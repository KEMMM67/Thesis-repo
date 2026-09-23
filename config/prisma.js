import { PrismaClient } from '@prisma/client';
import { fieldEncryptionExtension } from '../adapters/prisma/fieldEncryption.js';

// A single shared instance to avoid connection pool exhaustion. Extended
// with fieldEncryptionExtension so every consumer of this client -
// server.js, controllers/authController.js, prisma/seed.js, the WEVA
// adapters - reads and writes ENCRYPTED_FIELDS
// (adapters/prisma/fieldEncryption.js) as plain values automatically,
// with no per-call-site changes.
const prisma = new PrismaClient().$extends(fieldEncryptionExtension);

export default prisma;