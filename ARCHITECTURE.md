# Supply Chain Attestation & Deployment-Time Verification Gate
## Architecture Document

---

## 🎯 Project Goal

Demonstrate a real-world **software supply chain attack** and show how **cryptographic attestation** can detect and block it — using actual GitHub Actions, Docker Hub, and a live build server.

---

## 🗂️ Folder Structure

```
supplychainattest/
│
├── app/                        # The real application being built & deployed
│   ├── index.js                # Simple Node.js web server
│   ├── package.json
│   └── Dockerfile              # Docker image definition
│
├── build-server/               # The always-running build server ("production" machine)
│   ├── server.js               # Core: receives webhooks, pulls Docker images, verifies
│   ├── verifier.js             # Cryptographic hash + signature verification logic
│   ├── docker-manager.js       # Docker pull / run / stop operations via CLI
│   ├── package.json
│   └── dashboard/              # Web UI served at localhost:4000
│       ├── index.html
│       ├── style.css
│       └── app.js              # WebSocket client, live log feed, pipeline visualizer
│
├── attacker/                   # Attack simulator
│   ├── hack.js                 # Builds & pushes a malicious Docker image (same tag)
│   ├── malicious-app/          # Modified version of app/ with injected malware
│   │   ├── index.js            # App code + malware payload (data exfiltration sim)
│   │   ├── package.json
│   │   └── Dockerfile
│   └── package.json
│
├── keygen/                     # One-time key generation utility
│   ├── generate.js             # Generates RSA-2048 key pair for CI signing
│   └── package.json
│
├── .github/
│   └── workflows/
│       ├── vulnerable.yml      # ACT 1 & 2: CI with NO attestation (broken world)
│       └── protected.yml       # ACT 3: CI WITH attestation + signing (our fix)
│
└── ARCHITECTURE.md             # This file
```

---

## 🎭 The Three-Act Demo

### ACT 1 — The Normal World (No Protection)

```
Developer pushes code to GitHub
        │
        ▼
GitHub Actions (vulnerable.yml)
  • docker build -t user/app:latest .
  • docker push user/app:latest
  • POST /webhook → build server  { image: "user/app:latest" }
        │
        ▼
Build Server
  • docker pull user/app:latest
  • docker run -d -p 3000:3000 user/app:latest
  • ✅ App running — everything looks fine
```

**Problem**: The build server blindly trusts whatever is tagged `latest` on Docker Hub.

---

### ACT 2 — The Attack (Supply Chain Compromise)

```
Attacker runs: node attacker/hack.js
        │
        ▼
attacker/hack.js
  • Takes malicious-app/ (app + malware payload)
  • docker build -t user/app:latest malicious-app/
  • docker push user/app:latest    ← OVERWRITES the real image on Docker Hub
        │
Developer pushes next update (or build server auto-refreshes)
        │
        ▼
Build Server (no protection)
  • docker pull user/app:latest    ← Gets the MALICIOUS image
  • docker run ...                 ← MALWARE IS NOW RUNNING IN PRODUCTION 💀
  • GitHub logs show "Deployment successful" ← No alerts. Nothing caught it.
```

**The real SolarWinds scenario**: Source code in GitHub is 100% clean.
The CI/CD pipeline shows green. But production is running malware.

---

### ACT 3 — Our Fix (Attestation + Verification Gate)

```
Developer pushes code to GitHub
        │
        ▼
GitHub Actions (protected.yml)
  • docker build -t user/app:latest .
  • docker push user/app:latest
  • CAPTURE image digest → sha256:abc123...  ← Docker content hash, unique per image
  • SIGN the digest with CI_PRIVATE_KEY      ← Stored as GitHub Secret
  • POST /webhook → build server {
        image:     "user/app:latest",
        digest:    "sha256:abc123...",
        signature: "3a9f...",              ← Cryptographic proof from CI
        version:   "1.0.0"
    }
        │
        ▼
Build Server — Verification Gate
  ┌─────────────────────────────────────────┐
  │  1. Receive webhook                      │
  │  2. Verify SIGNATURE using CI public key │  ← Did this really come from GitHub?
  │  3. docker pull user/app:latest          │
  │  4. Get ACTUAL digest of pulled image    │  ← What did we actually get?
  │  5. Compare: expected digest vs actual   │  ← Do they match?
  │                                          │
  │  MATCH    → ✅ DEPLOY                   │
  │  MISMATCH → ❌ REJECT + ALERT           │
  └─────────────────────────────────────────┘

Attacker runs hack.js → pushes malicious image (new digest: sha256:xyz999...)
        │
        ▼
Build Server — Verification Gate
  • Signature valid:       ✅ (signed by CI, expected digest sha256:abc123...)
  • Actual pulled digest:  sha256:xyz999...
  • ❌ MISMATCH DETECTED
  • 🚨 SUPPLY CHAIN ATTACK BLOCKED — DEPLOYMENT REJECTED
```

---

## 🔐 Cryptographic Flow

### Key Generation (one-time setup)
```
keygen/generate.js
  └── Generates RSA-2048 key pair
        ├── private.pem  → Upload to GitHub Secrets as CI_PRIVATE_KEY
        └── public.pem   → Stored in build-server/keys/ci-public.pem
```

### Signing (GitHub Actions — protected.yml)
```javascript
// After docker push, GitHub Actions captures the image digest
const digest = "sha256:abc123...";

// Sign using CI private key (from GitHub Secrets)
const sign = crypto.createSign('SHA256');
sign.update(digest);
const signature = sign.sign(privateKey, 'hex');

// POST to build server
{ image, digest, signature, version }
```

### Verification (Build Server — verifier.js)
```javascript
// 1. Verify the signature — proves it came from our real CI pipeline
const verify = crypto.createVerify('SHA256');
verify.update(expectedDigest);
const isValid = verify.verify(ciPublicKey, signature, 'hex');

// 2. Get the actual digest of what Docker pulled
const actualDigest = execSync(
  `docker inspect --format="{{index .RepoDigests 0}}" ${image}`
).toString().trim();

// 3. Compare — catches ANY tampering with the image
if (actualDigest !== expectedDigest) → REJECT + ALERT
```

---

## 🌐 Component Communication

```
┌─────────────────┐   git push    ┌──────────────────┐
│  Developer (you)│ ────────────► │    GitHub Repo   │
└─────────────────┘               └────────┬─────────┘
                                           │ triggers workflow
                                           ▼
                                  ┌──────────────────┐
                                  │  GitHub Actions  │
                                  │  CI/CD Pipeline  │
                                  └──┬───────────────┘
                                     │ docker push
                                     ▼
                                  ┌──────────────────┐
                                  │   Docker Hub     │ ◄── Attacker also pushes here
                                  │  Image Registry  │
                                  └───────┬──────────┘
                    POST /webhook         │ docker pull
┌─────────────────┐ ◄───────────────────┐│
│  Build Server   │                      ││
│  port: 4000     │ ── pulls image ──────┘│
│                 │                       │
│  Verification   │                       │
│  Gate           │                       │
└────────┬────────┘                       │
         │ WebSocket (live logs)          │
         ▼                                │
┌─────────────────┐              ┌────────┴────────┐
│   Dashboard     │              │    Attacker     │
│  Live logs      │              │  (Terminal 2)   │
│  Pipeline viz   │              │  hack.js builds │
│  APPROVED /     │              │  & pushes bad   │
│  REJECTED       │              │  Docker image   │
└─────────────────┘              └─────────────────┘
```

---

## 🛠️ Tech Stack

| Component | Technology | Why |
|---|---|---|
| App | Node.js (no framework) | Minimal, easy to containerize |
| Build Server | Node.js + Express + `ws` | Real-time WebSocket log streaming |
| Docker Operations | Docker CLI via `child_process` | Works everywhere Docker is installed |
| Cryptography | Node.js built-in `crypto` | No extra deps, RSA-2048 signing |
| Dashboard UI | Vanilla HTML + CSS + JS | No build step, served as static files |
| CI/CD | GitHub Actions | Real, not simulated |
| Registry | Docker Hub | Real, not simulated |
| Attacker Script | Node.js + Docker CLI | Realistic — actually pushes to registry |

---

## 🚀 Setup & Demo Run Order

```bash
# STEP 1 — Generate signing keys (one time only)
cd keygen && npm install && node generate.js
# → Writes build-server/keys/ci-public.pem   (stays in repo)
# → Writes ci_private_key.txt                (add to GitHub Secrets)

# STEP 2 — Set these in GitHub repo Settings → Secrets → Actions
#   DOCKERHUB_USERNAME   = your Docker Hub username
#   DOCKERHUB_TOKEN      = Docker Hub access token
#   CI_PRIVATE_KEY       = contents of ci_private_key.txt
#   BUILD_SERVER_URL     = your build server URL (use ngrok for local)
#   BUILD_SERVER_TOKEN   = any random secret string

# STEP 3 — Start Build Server (Terminal 1 — leave running all demo)
cd build-server && npm install && npm start
# Terminal streams live logs
# Dashboard → http://localhost:4000

# ── DEMO DAY ─────────────────────────────────────────

# ACT 1: Push code with vulnerable pipeline
# Use vulnerable.yml, push a commit to GitHub
# → Actions runs → image on Docker Hub → build server deploys ✅

# ACT 2: Attack! (Terminal 2)
cd attacker && npm install && node hack.js
# → Malicious image pushed to Docker Hub with same tag
# → Push again → build server runs malware with no warning 💀

# ACT 3: Switch to protected pipeline + push
# Use protected.yml, push a commit
# → Actions signs digest → build server catches mismatch → ❌ REJECTED 🚨
```

---

## 📋 GitHub Secrets Required

| Secret Name | Value | Used By |
|---|---|---|
| `DOCKERHUB_USERNAME` | Your Docker Hub username | Both workflows |
| `DOCKERHUB_TOKEN` | Docker Hub access token | Both workflows |
| `CI_PRIVATE_KEY` | RSA private key PEM (from keygen/) | `protected.yml` only |
| `BUILD_SERVER_URL` | Public URL of your build server | Both workflows |
| `BUILD_SERVER_TOKEN` | Shared secret for webhook auth | Both workflows |
