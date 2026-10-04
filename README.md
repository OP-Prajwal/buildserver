# Supply Chain Attestation & Deployment-Time Verification Gate

A production-ready demo of a software supply chain attack and how cryptographic attestation stops it.

**Stack**: Real GitHub Actions · Real Docker Hub · Real cosign (Sigstore) · Real Syft SBOM

---

## 📁 Structure

```
supplychainattest/
├── app/                        → The app being built & deployed
├── build-server/               → Always-running verification gate + dashboard
├── attacker/                   → Attack simulator (overwrites Docker Hub tag)
└── .github/workflows/
    ├── vulnerable.yml          → CI with NO attestation  (ACT 1 & 2)
    └── protected.yml           → CI WITH cosign + SBOM   (ACT 3)
```

---

## ⚡ Quick Start

### 1. Prerequisites

```bash
# On the build server machine:
# Install cosign
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign
cosign version

# Docker must be running
docker info
```

### 2. Clone & Configure

```bash
git clone https://github.com/YOUR_USERNAME/supplychainattest
cd supplychainattest
```

Copy and fill in the build server config:
```bash
cp build-server/.env.example build-server/.env
# Edit build-server/.env:
#   GITHUB_REPO=YOUR_USERNAME/supplychainattest
#   BUILD_SERVER_TOKEN=any-random-secret-string
```

Copy and fill in the attacker config:
```bash
cp attacker/.env.example attacker/.env
# Edit attacker/.env:
#   DOCKERHUB_USERNAME=your-dockerhub-username
```

### 3. Set GitHub Secrets

In your repo → Settings → Secrets → Actions, add:

| Secret | Value |
|--------|-------|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token (create at hub.docker.com) |
| `BUILD_SERVER_URL` | Public URL of your build server (use [ngrok](https://ngrok.com) for local) |
| `BUILD_SERVER_TOKEN` | Same random string as in `build-server/.env` |

> `CI_PRIVATE_KEY` is **not needed** — we use cosign **keyless signing** via GitHub OIDC.
> No private keys to manage. The identity is the workflow file itself.

### 4. Expose build server with ngrok (for local demo)

```bash
# Terminal 1 — start ngrok
ngrok http 4000
# Copy the https://xxxx.ngrok.io URL → set as BUILD_SERVER_URL GitHub Secret
```

### 5. Install dependencies

```bash
# Build server
cd build-server && npm install

# Attacker
cd ../attacker && npm install
```

### 6. Start the build server

```bash
# Terminal 2 — leave this running all demo
cd build-server
npm start

# Dashboard → http://localhost:4000
```

---

## 🎭 Demo

### ACT 1 — Normal world (no protection)

1. Make sure `app/` has clean code
2. In GitHub → Actions, run **"Vulnerable Pipeline (No Attestation)"** (or push to `main`)
3. Watch build server logs: image pulls, container starts → **✅ DEPLOYED**

### ACT 2 — Supply chain attack

```bash
# Terminal 3 — run the attacker
cd attacker
node hack.js
```

This builds the malicious image and **overwrites** `youruser/supplychainattest-app:latest` on Docker Hub.

4. Run **Vulnerable Pipeline** again (push a commit)
5. Watch build server: pulls `:latest` → gets **malicious image** → **💀 MALWARE DEPLOYED**
6. GitHub Actions shows green. No alerts. The CI never knew.

### ACT 3 — Attestation blocks the attack

6. Run **"Protected Pipeline (Attestation + Cosign)"**
   - cosign signs the image (keyless, via GitHub OIDC)
   - Syft generates SBOM
   - cosign attaches SBOM as attestation
   - Build server receives webhook

7. Build server runs 4 checks:
   ```
   ✔ 1. cosign verify         — image was signed by this exact workflow
   ✔ 2. cosign verify-attest  — SBOM attestation exists and is from CI
   ✔ 3. docker pull (digest)  — pulled by SHA256, not by tag
   ✔ 4. digest verify         — local image matches what CI signed
   ```

8. Run the attacker again → run Protected Pipeline again
9. Build server: **❌ REJECTED — signature verification failed**
   - The attacker's image has no valid cosign signature
   - Dashboard shows: `🚨 DEPLOYMENT REJECTED`

---

## 🔐 How the Verification Works

```
GitHub Actions (protected.yml)
  │
  ├─ docker push → digest: sha256:abc123...
  ├─ cosign sign (OIDC) → signature stored in Rekor transparency log
  ├─ syft → sbom.spdx.json
  ├─ cosign attest --type spdxjson → SBOM attestation in registry
  └─ POST /webhook { image, digest, mode: "protected" }

Build Server (verifier.js)
  │
  ├─ cosign verify
  │    --certificate-identity=.../protected.yml@refs/heads/main
  │    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
  │    image@digest
  │    → ✅ signature valid (from our CI) or ❌ reject
  │
  ├─ cosign verify-attestation --type spdxjson image@digest
  │    → ✅ SBOM attested by CI or ❌ reject
  │
  ├─ docker pull image@digest  (by digest, not tag — tag hijack irrelevant)
  │
  └─ docker inspect → actual digest == expected digest
       → ✅ deploy or ❌ reject
```

---

## 📦 What cosign Keyless Signing Means

- **No private key is stored anywhere** in this repo or on the build server
- GitHub Actions gets a short-lived OIDC token proving it is running as `protected.yml @ main`
- Sigstore's Fulcio CA issues a certificate for that identity
- The signature + certificate are recorded in Rekor (public transparency log)
- The build server verifies by checking: *"Was this signed by a cert issued for exactly this workflow?"*
- If the attacker pushes a different image → it has no signature → `cosign verify` fails → **REJECTED**

---

## 🛠 Troubleshooting

| Problem | Fix |
|---------|-----|
| `cosign verify` fails with "no signatures found" | The image wasn't pushed via `protected.yml` — use the protected workflow |
| Build server doesn't receive webhook | Check ngrok is running and `BUILD_SERVER_URL` secret is up to date |
| `HMAC signature mismatch` in server logs | `BUILD_SERVER_TOKEN` doesn't match between `.env` and GitHub Secrets |
| Docker pull fails | Make sure build server machine is logged in to Docker Hub: `docker login` |
| Dashboard not updating | Check WebSocket connection — green dot in top right should show "Live" |
