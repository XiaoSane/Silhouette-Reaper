# ◈ SILHOUETTE REAPER ◈
### Anonymous Public Digital Forensics Investigation Platform

[![Next.js 14](https://img.shields.io/badge/Next.js-14.2-black?logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-3.4-38bdf8?logo=tailwind-css)](https://tailwindcss.com/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-amber.svg)](LICENSE)
[![Cryptographic Sealing](https://img.shields.io/badge/Merkle%20Root-SHA--256-10b981)](#cryptographic-merkle-sealing)

> **Silhouette Reaper** is a zero-account, verifiable, cryptographically sealed digital forensics platform designed for whistleblowers, investigative journalists, human rights organizations, and cybersecurity incident responders.
> 
> Treat untrusted digital evidence with bit-stream rigor, reconstruct forensic timelines across heterogeneous sources, extract hidden indicators of compromise, and generate publication-grade forensic reports with verifiable Merkle tree seals.

---

## ✦ Key Architectural Pillars

### 1. Zero-Account Anonymous Sessions
- **Cryptographically Unpredictable Session IDs**: Formatted as `INV-YYYY-XXXXXXXX` generated with 128-bit cryptographic entropy.
- **Constant-Time Secret Validation**: High-entropy 256-bit session secret key validated using `crypto.timingSafeEqual` to prevent timing side-channel attacks.
- **Configurable Lifecycle & Zero-Fill Shredding**: Automatic 24-hour retention cleanup with instantaneous zero-fill disk and database shredding.

### 2. Bit-Stream Read-Only Evidence Vault
- **Zero Evidence Execution**: Untrusted evidence files are treated strictly as hostile binary streams.
- **Streaming Multi-Algorithm Hashing**: Authoritative FIPS 180-4 **SHA-256**, alongside **SHA-1** and **MD5** compatibility digests computed on ingest.
- **Immutable Storage**: Evidence is written to disk with read-only permissions (`0444 / 0400`) and opened strictly with `O_RDONLY` file descriptors.

### 3. Modular Forensic Processing Pipeline
- **File Identification & Magic Byte Sniffing**: Inspects true binary magic bytes (PE, ELF, PDF, ZIP, Office OpenXML, EVTX, JPEG, PNG, SQLite) and calculates byte-level Shannon entropy ($0.00 - 8.00$).
- **EXIF & Image Metadata Engine**: Extracts camera make/model, lens specifications, exposure, GPS coordinates (latitude, longitude, altitude), and timestamps (`DateTimeOriginal`, `CreateDate`, `ModifyDate`).
- **PDF Deep Inspection Engine**: Analyzes document catalogs, trailer dictionaries, incremental update counts (`%%EOF`), encryption flags, and flags malicious embedded active code (`/JavaScript`, `/JS`, `/Launch`, `/OpenAction`).
- **Office OpenXML (DOCX, XLSX, PPTX) Engine**: Inspects OPC packages for revision history, hidden worksheets, external relationships, and embedded VBA macro streams (`vbaProject.bin`).
- **Archive & Container Engine**: Protects against zip bombs ($> 250\text{ MB}$ or $> 100:1$ compression ratios), detects nested archive evasion, and catches Zip Slip directory traversal attacks (`../`).
- **Log & Telemetry Engine**: Ingests Syslog, Apache/Nginx W3C access logs, Windows Event payloads, detecting SQLi (`UNION SELECT`), directory traversal (`/etc/passwd`), and command injection.
- **Strings & IOC Extraction**: Identifies ASCII/Unicode strings, IPv4/IPv6 addresses, URLs, email addresses, Windows/Unix file paths, registry keys, and execution tokens.
- **Defensible Findings Correlator**: Enforces strict correlation rules (Extension Spoofing, Timestomping, Macro Anomalies, Zip Slip, Web Reconnaissance) with mandatory non-empty artifact provenance linking.

### 4. Publication-Grade Forensic PDF Reports & Merkle Tree Sealer
- Deterministic, vector-crisp PDF generation via `pdf-lib`.
- Complete multi-page report structure: Scope, Chain of Custody, Evidence Manifest, Tool Inventory, Extracted Artifacts, Unified Chronological Timeline, Correlated Findings, Limitations, and Cryptographic Seal.
- Sealer computes a deterministic **Merkle Tree Root** over all artifacts and findings.
- **Independent Public Verification Portal** (`/verify`): Enables any third party to verify report authenticity and hash integrity via a verification token (`VRF-XXXX-XXXX-XXXX`) or SHA-256 digest.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Framework** | [Next.js 14](https://nextjs.org/) (App Router, Server Actions, API Handlers) |
| **Language** | [TypeScript 5.7](https://www.typescriptlang.org/) (Strict Mode) |
| **Styling** | [Tailwind CSS 3.4](https://tailwindcss.com/) + Custom Tactical Cyberpunk Design Tokens |
| **UI Components** | [Lucide React](https://lucide.dev/), Custom Glassmorphism UI |
| **Forensic Engines** | `exif-parser`, `pdf-lib`, `adm-zip`, Native Node.js `crypto` & binary decoders |
| **Validation** | [Zod 3.24](https://zod.dev/) |
| **Containerization** | Docker, Docker Compose, Multi-stage Node.js Alpine build |
| **Reverse Proxy** | Nginx & Caddy production configurations |

---

## 🚀 Quick Start (Local Development)

### 1. Prerequisites
- **Node.js**: `v20.x` or `v22.x`
- **npm**: `v10+`

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/XiaoSane/Silhouette-Reaper.git
cd Silhouette-Reaper

# Install dependencies
npm install
```

### 3. Run Development Server
```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser to launch the forensic terminal.

### 4. Run Forensic Unit Tests
```bash
npx ts-node --compiler-options '{"module":"commonjs"}' tests/unit_forensic_engines.test.ts
```

---

## 🐳 Docker Deployment

A production-ready `Dockerfile` and `docker-compose.yml` are included.

```bash
# Build and run the container in detached mode
docker compose up -d --build

# Inspect logs
docker compose logs -f
```

The application will be accessible at [http://localhost:3000](http://localhost:3000) with persistent storage mapped to `./storage`.

Detailed production deployment guides (including Nginx reverse proxy, SSL/TLS, and systemd service setup) can be found in:
📖 **[docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)**

---

## 📁 Repository Structure

```text
├── .gitignore
├── Dockerfile
├── LICENSE
├── README.md
├── deploy/
│   ├── Caddyfile
│   ├── nginx.conf
│   └── silhouette-reaper.service
├── docker-compose.yml
├── docs/
│   ├── PRODUCTION_DEPLOYMENT.md
│   └── css_design_system_and_styling_guide.md
├── package.json
├── public/
│   └── logo.svg
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── evidence/
│   │   │   ├── investigations/
│   │   │   ├── reports/
│   │   │   └── verify/
│   │   ├── globals.css
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   ├── verify/
│   │   └── workspace/
│   ├── components/
│   │   ├── forensic/
│   │   ├── layout/
│   │   └── ui/
│   ├── lib/
│   │   ├── db/
│   │   ├── engines/
│   │   ├── report/
│   │   └── utils/
│   └── types/
│       └── forensics.ts
├── tests/
│   ├── e2e_investigation_lifecycle.ts
│   └── unit_forensic_engines.test.ts
└── tsconfig.json
```

---

## 🛡️ Security & Privacy Model

1. **Zero Personally Identifiable Information (PII)**: No user registration, no email required, no third-party tracking cookies or external analytical beacons.
2. **Ephemeral Storage**: All artifacts, evidence binary streams, and database entries are scoped to transient investigation sessions.
3. **Defense in Depth**: Uploaded files are strictly isolated in a read-only vault; parsers operate memory-safely without shell execution or script evaluation.
4. **Independent Verification**: Anyone holding a generated forensic examination report can verify its integrity without authenticating to the platform.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.