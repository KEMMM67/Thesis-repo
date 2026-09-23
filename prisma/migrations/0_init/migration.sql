-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('student', 'faculty', 'admin');

-- CreateEnum
CREATE TYPE "LoginStatus" AS ENUM ('SUCCESS', 'FAILED');

-- CreateEnum
CREATE TYPE "RiskLevel" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "ActionTaken" AS ENUM ('ALLOW', 'LOG', 'THROTTLE', 'BLOCK');

-- CreateEnum
CREATE TYPE "StudentStatus" AS ENUM ('ENROLLED', 'IRREGULAR', 'DROPPED');

-- CreateTable
CREATE TABLE "users" (
    "id" SERIAL NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "password_hash" VARCHAR(255) NOT NULL,
    "role" "Role" NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "otp_code" VARCHAR(6),
    "otp_expires_at" TIMESTAMP(3),

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "login_attempts" (
    "id" SERIAL NOT NULL,
    "user_email" VARCHAR(255) NOT NULL,
    "user_id" INTEGER,
    "ip_address" VARCHAR(45) NOT NULL,
    "status" "LoginStatus",
    "attempt_time" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "login_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "anomaly_scores" (
    "id" SERIAL NOT NULL,
    "user_email" VARCHAR(255) NOT NULL,
    "user_id" INTEGER,
    "score" DECIMAL(5,2) NOT NULL,
    "risk_level" "RiskLevel",
    "calculated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "anomaly_scores_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_actions" (
    "id" SERIAL NOT NULL,
    "user_email" VARCHAR(255) NOT NULL,
    "user_id" INTEGER,
    "action_taken" "ActionTaken",
    "reason" TEXT,
    "action_time" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_actions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "behavior_logs" (
    "id" SERIAL NOT NULL,
    "user_email" VARCHAR(255),
    "user_id" INTEGER,
    "event_type" VARCHAR(100) NOT NULL,
    "description" TEXT,
    "log_time" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "behavior_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" SERIAL NOT NULL,
    "user_id" INTEGER,
    "session_token" VARCHAR(255) NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ip_tracking" (
    "id" SERIAL NOT NULL,
    "ip_address" VARCHAR(45) NOT NULL,
    "total_requests" INTEGER NOT NULL DEFAULT 0,
    "is_blocked" BOOLEAN NOT NULL DEFAULT false,
    "blocked_until" TIMESTAMP(3),
    "last_seen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ip_tracking_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "students" (
    "id" SERIAL NOT NULL,
    "student_id" VARCHAR(20) NOT NULL,
    "full_name" VARCHAR(255) NOT NULL,
    "department" VARCHAR(100) NOT NULL DEFAULT '',
    "program" VARCHAR(150) NOT NULL DEFAULT '',
    "year_level" VARCHAR(50) NOT NULL DEFAULT '',
    "status" "StudentStatus" NOT NULL DEFAULT 'ENROLLED',
    "user_id" INTEGER,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "students_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "subjects" (
    "id" SERIAL NOT NULL,
    "subject_code" VARCHAR(20) NOT NULL,
    "subject_title" VARCHAR(255) NOT NULL,
    "units" INTEGER NOT NULL DEFAULT 3,
    "department" VARCHAR(100) NOT NULL DEFAULT '',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "subjects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "grades" (
    "id" SERIAL NOT NULL,
    "student_id" INTEGER NOT NULL,
    "subject_id" INTEGER NOT NULL,
    "term" VARCHAR(50),
    "grade" VARCHAR(255),
    "remarks" VARCHAR(50),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "grades_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "login_attempts_user_id_idx" ON "login_attempts"("user_id");

-- CreateIndex
CREATE INDEX "login_attempts_attempt_time_idx" ON "login_attempts"("attempt_time");

-- CreateIndex
CREATE INDEX "login_attempts_user_email_idx" ON "login_attempts"("user_email");

-- CreateIndex
CREATE INDEX "anomaly_scores_user_id_idx" ON "anomaly_scores"("user_id");

-- CreateIndex
CREATE INDEX "anomaly_scores_calculated_at_idx" ON "anomaly_scores"("calculated_at");

-- CreateIndex
CREATE INDEX "security_actions_user_id_idx" ON "security_actions"("user_id");

-- CreateIndex
CREATE INDEX "security_actions_action_time_idx" ON "security_actions"("action_time");

-- CreateIndex
CREATE INDEX "behavior_logs_user_id_idx" ON "behavior_logs"("user_id");

-- CreateIndex
CREATE INDEX "behavior_logs_log_time_idx" ON "behavior_logs"("log_time");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_session_token_key" ON "sessions"("session_token");

-- CreateIndex
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "ip_tracking_ip_address_key" ON "ip_tracking"("ip_address");

-- CreateIndex
CREATE UNIQUE INDEX "students_student_id_key" ON "students"("student_id");

-- CreateIndex
CREATE UNIQUE INDEX "students_user_id_key" ON "students"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "subjects_subject_code_key" ON "subjects"("subject_code");

-- CreateIndex
CREATE INDEX "grades_student_id_idx" ON "grades"("student_id");

-- CreateIndex
CREATE INDEX "grades_subject_id_idx" ON "grades"("subject_id");

-- CreateIndex
CREATE UNIQUE INDEX "grades_student_id_subject_id_term_key" ON "grades"("student_id", "subject_id", "term");

-- AddForeignKey
ALTER TABLE "login_attempts" ADD CONSTRAINT "login_attempts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "anomaly_scores" ADD CONSTRAINT "anomaly_scores_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_actions" ADD CONSTRAINT "security_actions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "behavior_logs" ADD CONSTRAINT "behavior_logs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "students" ADD CONSTRAINT "students_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "grades" ADD CONSTRAINT "grades_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "students"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "grades" ADD CONSTRAINT "grades_subject_id_fkey" FOREIGN KEY ("subject_id") REFERENCES "subjects"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

