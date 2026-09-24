/**
 * @fileoverview Streams an application-level JSON snapshot of every table
 * (GET /api/admin/backup in server.js).
 *
 * Why it streams: the snapshot holds 15,000+ students, 45,000+ grades and
 * every audit row WEVA has ever written. Building all of that as one
 * object before sending it (what this route used to do) holds the whole
 * database in memory at once on a 512 MB instance. Here each table is read
 * in keyset-paged batches (`id > lastId ORDER BY id LIMIT n`) and written
 * out as it arrives, so memory use depends on the batch size, not the
 * database size.
 *
 * Why one transaction: every batch runs inside a single REPEATABLE READ
 * transaction, so all tables come from the same instant - a grade can
 * never reference a student row the snapshot missed because it was
 * inserted halfway through the export. In Postgres a read-only REPEATABLE
 * READ transaction never blocks writers.
 *
 * What is deliberately NOT in the file:
 *   - User.passwordHash, User.otpCode/otpExpiresAt - credentials are worse
 *     off in a downloadable file than in the database.
 *   - The Session table - it holds live bearer tokens.
 *   - Plaintext grades: Grade.grade is read with raw SQL, which the
 *     field-encryption extension (adapters/prisma/fieldEncryption.js) does
 *     not intercept, so each grade is exported exactly as stored - an
 *     AES-256-GCM envelope. The file inherits the database's at-rest
 *     protection; reading a grade back requires FIELD_ENCRYPTION_KEY,
 *     which is never exported.
 */

const FORMAT = 'sis-json-snapshot/v1';
const DEFAULT_BATCH_SIZE = 5000;
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

const ENCRYPTION_NOTE = {
    'grades.grade': 'AES-256-GCM envelope "iv:authTag:ciphertext" (base64 segments), exported exactly as stored. Decrypting requires FIELD_ENCRYPTION_KEY, which is never part of an export.'
};

/**
 * The tables in export order, each with a reader returning up to `take`
 * rows whose id is greater than `afterId`, in ascending id order.
 *
 * @param {object} db - Prisma client, or the transaction client inside $transaction.
 * @returns {Array<[string, (afterId: number, take: number) => Promise<object[]>]>}
 */
function exportTables(db) {
    const pageOf = (model, extra = {}) => (afterId, take) =>
        model.findMany({ where: { id: { gt: afterId } }, orderBy: { id: 'asc' }, take, ...extra });

    return [
        ['users', pageOf(db.user, { select: { id: true, email: true, role: true, createdAt: true } })],
        ['students', pageOf(db.student)],
        ['subjects', pageOf(db.subject)],
        ['grades', (afterId, take) => db.$queryRaw`
            SELECT id, student_id AS "studentId", subject_id AS "subjectId", term, grade, remarks,
                   created_at AS "createdAt", updated_at AS "updatedAt"
            FROM grades
            WHERE id > ${afterId}
            ORDER BY id ASC
            LIMIT ${take}`],
        ['loginAttempts', pageOf(db.loginAttempt)],
        ['anomalyScores', pageOf(db.anomalyScore)],
        ['securityActions', pageOf(db.securityAction)],
        ['behaviorLogs', pageOf(db.behaviorLog)],
        ['ipTracking', pageOf(db.ipTracking)]
    ];
}

/**
 * Writes `chunk`, waiting for 'drain' when the stream's buffer is full, so a
 * slow download pauses the database reads instead of piling rows up in
 * memory. Rejects if the stream closes first (e.g. the admin cancelled the
 * download), which ends the export and rolls the transaction back.
 *
 * @param {import('stream').Writable} out
 * @param {string} chunk
 * @returns {Promise<void>}
 */
function write(out, chunk) {
    if (out.destroyed) return Promise.reject(new Error('Export stream closed before the snapshot finished.'));
    if (out.write(chunk)) return Promise.resolve();

    return new Promise((resolve, reject) => {
        const onDrain = () => { cleanup(); resolve(); };
        const onClose = () => { cleanup(); reject(new Error('Export stream closed before the snapshot finished.')); };
        const cleanup = () => {
            out.off('drain', onDrain);
            out.off('close', onClose);
        };
        out.on('drain', onDrain);
        out.on('close', onClose);
    });
}

/**
 * Writes the whole snapshot to `out` as one JSON object - metadata first,
 * then one array per table, one row per line. Does not end `out`: the
 * caller does, once this resolves. If this rejects partway through, the
 * JSON written so far is incomplete, so the caller must abort the response
 * rather than end it - a truncated file must never look like a finished one.
 *
 * @param {object} db - Prisma client (config/prisma.js).
 * @param {import('stream').Writable} out - Typically the Express response.
 * @param {object} meta
 * @param {string} meta.generatedBy - Email of the admin who requested the export.
 * @param {Date} [meta.generatedAt]
 * @param {number} [meta.batchSize] - Rows per database round trip.
 * @param {number} [meta.timeoutMs] - Upper bound on the whole export transaction.
 * @returns {Promise<void>}
 */
export async function streamDatabaseExport(db, out, { generatedBy, generatedAt = new Date(), batchSize = DEFAULT_BATCH_SIZE, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    await db.$transaction(async (tx) => {
        const header = [
            `"format": ${JSON.stringify(FORMAT)}`,
            `"generatedAt": ${JSON.stringify(generatedAt.toISOString())}`,
            `"generatedBy": ${JSON.stringify(generatedBy)}`,
            `"consistency": "Single REPEATABLE READ transaction - every table reflects the same instant."`,
            `"encryption": ${JSON.stringify(ENCRYPTION_NOTE)}`
        ];
        await write(out, `{\n${header.join(',\n')}`);

        for (const [name, readPage] of exportTables(tx)) {
            await write(out, `,\n${JSON.stringify(name)}: [`);

            let separator = '\n';
            let afterId = 0;
            for (;;) {
                const rows = await readPage(afterId, batchSize);
                if (rows.length > 0) {
                    let chunk = '';
                    for (const row of rows) {
                        chunk += separator + JSON.stringify(row);
                        separator = ',\n';
                    }
                    await write(out, chunk);
                    afterId = rows[rows.length - 1].id;
                }
                if (rows.length < batchSize) break;
            }

            await write(out, '\n]');
        }

        await write(out, '\n}\n');
    }, { isolationLevel: 'RepeatableRead', timeout: timeoutMs, maxWait: 10_000 });
}
