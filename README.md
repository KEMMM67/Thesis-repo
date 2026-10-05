# Agentic Runtime Application Security Framework

> Adaptive runtime application security with behavioral profiling — purpose-built for Student Information Systems.

[![Node.js](https://img.shields.io/badge/Node.js-24-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-5.x-000000?style=flat-square&logo=express&logoColor=white)](https://expressjs.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Prisma](https://img.shields.io/badge/Prisma-ORM-2D3748?style=flat-square&logo=prisma&logoColor=white)](https://www.prisma.io/)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen?style=flat-square)]()
[![License](https://img.shields.io/badge/license-ISC-blue?style=flat-square)]()

---

## Overview

The **Agentic Runtime Application Security Framework** is a self-contained runtime application self-protection (RASP) layer that sits in front of a Student Information System and defends it while it runs — not before deployment, and not by inspecting logs after the fact. Instead of relying on static rule sets or binary allow/deny lists, the framework builds a **behavioral profile** for every user session in real time, scores each incoming request against that profile using an exponential moving average (EMA), and only escalates to mitigation when a request pattern crosses a statistically meaningful threshold.

This design is deliberate: legitimate traffic is bursty. A registrar uploading grades for an entire section, or a student refreshing a dashboard during enrollment week, should never be mistaken for an attacker. The framework's **bounded decision logic** exists specifically to separate genuine behavioral anomalies — brute-force login attempts, credential stuffing, denial-of-service floods — from ordinary spikes in legitimate usage, so mitigation is only ever triggered on actual attack patterns.

The framework is the security core of a full-stack Student Information System, but it is architected to be portable: the detection and mitigation engine has no knowledge of Express, PostgreSQL, or Prisma. It communicates with the rest of the application exclusively through defined ports, which is what makes it an *agentic, pluggable* defense layer rather than a bolt-on middleware script.

## System Architecture

The framework is built on **Hexagonal Architecture** (Ports and Adapters), which strictly isolates the security domain from infrastructure concerns:

```
                     ┌─────────────────────────────┐
                     │   Express.js Routing Layer   │
                     │   (controllers, middleware)  │
                     └──────────────┬───────────────┘
                                    │  adapts to
                                    ▼
                     ┌─────────────────────────────┐
                     │            Ports             │
                     │   (core/ports.js contracts)  │
                     └──────────────┬───────────────┘
                                    │  implemented by
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │                    Core Domain                     │
        │  profiler → monitor → scorer → decisionEngine      │
        │                → mitigation → logger               │
        └──────────────────────────┬──────────────────────────┘
                                    │  persisted via
                                    ▼
                     ┌─────────────────────────────┐
                     │   Prisma / PostgreSQL Adapter │
                     │        (adapters/prisma)      │
                     └─────────────────────────────┘
```

- **Core (`/core`)** — Pure domain logic: behavioral profiling, EMA-based scoring, decision-making, and mitigation policy. This layer has zero dependencies on Express or Prisma and is fully unit-testable in isolation.
- **Ports (`core/ports.js`)** — The contracts the core domain expects from the outside world (state persistence, notification, etc.), so the domain never talks to infrastructure directly.
- **Adapters (`/adapters`)** — Concrete implementations of those ports, including the Prisma/PostgreSQL persistence adapter.
- **Inbound edge (`/routes`, `/controllers`, `/middleware`)** — Express.js wires HTTP traffic into the core through `middleware/securityMiddleware.js`, translating raw requests into events the domain can score.

This separation means the detection algorithm can be tested, reasoned about, and swapped in isolation — the mitigation logic doesn't change if the database or web framework changes underneath it.

## Key Features

- **Behavioral Profiling Engine** — Builds a rolling per-user/per-session profile of request behavior and updates it continuously using an exponential moving average, weighting recent activity more heavily than historical noise.
- **Real-Time Attack Detection** — Flags brute-force login attempts, DoS floods, and distributed DDoS-style traffic patterns as they happen, without batch processing or offline log analysis.
- **Bounded Decision Logic** — A decision engine (`core/decisionEngine.js`) that gates mitigation behind confidence thresholds, ensuring legitimate traffic spikes (e.g., bulk grade uploads, enrollment-period logins) are never misclassified as attacks.
- **Graduated Mitigation** — Configurable response tiers (suspicious → critical → block) with time-boxed throttling, rather than a blunt permanent ban.
- **Hexagonal Architecture** — Ports-and-adapters design that keeps the security core fully decoupled from Express.js and Prisma/PostgreSQL, enabling isolated testing and framework portability.
- **Cryptographically Secure OTP** — One-time passwords generated with a CSPRNG (`crypto.randomInt`/`crypto.randomBytes`), never `Math.random()`.
- **Constant-Time Secret Comparison** — Uses `crypto.timingSafeEqual` for OTP and token verification to eliminate timing side-channel attacks.
- **Encryption at Rest** — Sensitive fields are encrypted with **AES-256-GCM**, providing both confidentiality and authenticated integrity for data stored in PostgreSQL.
- **Defense-in-Depth Middleware** — Rate limiting, HTTP security headers (via Helmet), CORS policy enforcement, and optional IP allowlisting for administrative access.

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js |
| Web Framework | Express.js |
| Database | PostgreSQL |
| ORM | Prisma |
| Auth | JSON Web Tokens (JWT), bcrypt |
| Testing | Vitest |
| Load Testing | k6 |

## Getting Started

### Prerequisites

- Node.js 24 (pinned via `engines` in package.json)
- A running PostgreSQL instance
- npm

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/KEMMM67/Student_Info_System.git
cd Student_Info_System

# 2. Install dependencies
npm install

# 3. Configure environment variables
cp .env.example .env
```

Populate `.env` with your own values:

```env
DATABASE_URL=postgresql://user:password@host:5432/database

PORT=3000
JWT_SECRET=

# Behavioral profiling / EMA tuning
SECURITY_WINDOW_MS=
SECURITY_EMA_ALPHA=
SECURITY_THRESHOLD_SUSPICIOUS=
SECURITY_THRESHOLD_CRITICAL=
SECURITY_THRESHOLD_BLOCK=
SECURITY_MITIGATION_BLOCK_MS=

# Mail (OTP delivery)
SMTP_EMAIL=
SMTP_APP_PASSWORD=

# Cryptography
FIELD_ENCRYPTION_KEY=

# Optional hardening
ENABLE_HTTPS=
ENABLE_IP_WHITELIST=
ALLOWED_ADMIN_IPS=
```

```bash
# 4. Run database migrations
npx prisma migrate dev

# 5. Start the development server (nodemon, opens the browser on Windows)
npm run dev
```

### Running Tests

```bash
npm test
```

## Author

**Khynne Mark Elmer L. Lawan**
GitHub: [@KEMMM67](https://github.com/KEMMM67)

---

*This project is developed as part of an undergraduate thesis on adaptive, behavior-driven runtime security for Student Information Systems.*
