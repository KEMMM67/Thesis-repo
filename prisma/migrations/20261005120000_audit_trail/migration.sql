-- CreateEnum
CREATE TYPE "AuditOutcome" AS ENUM ('SUCCESS', 'FAILURE');

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" SERIAL NOT NULL,
    "occurred_at" TIMESTAMP(3) NOT NULL,
    "actor_user_id" INTEGER,
    "actor_email" VARCHAR(255) NOT NULL,
    "actor_role" VARCHAR(20) NOT NULL,
    "action" VARCHAR(50) NOT NULL,
    "entity_type" VARCHAR(50) NOT NULL,
    "entity_id" VARCHAR(150) NOT NULL,
    "outcome" "AuditOutcome" NOT NULL,
    "status_code" INTEGER NOT NULL,
    "ip_address" VARCHAR(45),
    "device_id" VARCHAR(45),
    "detail" TEXT,
    "prev_hash" CHAR(64) NOT NULL,
    "hash" CHAR(64) NOT NULL,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "audit_logs_hash_key" ON "audit_logs"("hash");

-- CreateIndex
CREATE INDEX "audit_logs_occurred_at_idx" ON "audit_logs"("occurred_at");

-- CreateIndex
CREATE INDEX "audit_logs_actor_email_idx" ON "audit_logs"("actor_email");

-- CreateIndex
CREATE INDEX "audit_logs_entity_type_entity_id_idx" ON "audit_logs"("entity_type", "entity_id");


-- Append-only, enforced by the database itself (hand-written: Prisma's
-- schema language has no triggers). Any UPDATE, DELETE or TRUNCATE on
-- audit_logs fails, whether it comes from this app, a seed script, or
-- someone at a psql prompt holding the app's credentials. A superuser can
-- still disable these triggers - that is what the HMAC chain on every row
-- is for: changing a row after doing so is detected at that row by
-- GET /api/admin/audit/verify (see utils/auditTrail.js).
CREATE FUNCTION "audit_logs_reject_change"() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "audit_logs_no_update_or_delete"
    BEFORE UPDATE OR DELETE ON "audit_logs"
    FOR EACH ROW EXECUTE FUNCTION "audit_logs_reject_change"();

CREATE TRIGGER "audit_logs_no_truncate"
    BEFORE TRUNCATE ON "audit_logs"
    FOR EACH STATEMENT EXECUTE FUNCTION "audit_logs_reject_change"();
