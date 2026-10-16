# AttestGate — End-to-End Supply Chain Attestation & Deployment Gate
## System Architecture Specification (`NEW_ARCHITECTURE.md`)

---

## 1. Executive Summary & Vision

> This document describes planned product capabilities. The current implemented runtime is the Kubernetes admission controller documented in `ARCHITECTURE.md`; the control plane, PR integration, policy management, and cluster enrollment below are not implemented yet.

Modern engineering teams rely heavily on automated CI/CD pipelines and container registries (e.g., Docker Hub, AWS ECR, GitHub Packages). However, current container runtime engines and Kubernetes clusters operate on **blind trust**: they pull whichever image happens to match a tag (such as `:latest` or `:v1.2.0`).

If an attacker compromises developer credentials, a registry token, or an automated pipeline step, they can overwrite an image with malicious code. **The GitHub repository remains completely clean, code review passes, yet production executes malware.**

**AttestGate** is a zero-trust supply chain security platform that links code review on GitHub directly to runtime admission in production clusters (Docker / Kubernetes).

---

## 2. Core Personas & System Workflow

```
[ Product / Sec Lead ]          [ Developers ]               [ CI/CD Engine ]          [ Target Cluster ]
         │                            │                             │                          │
  1. Invites team              2. Opens Pull Request                 │                          │
  2. Connects GitHub repo             │                             │                          │
  3. Sets deployment policy    3. Reviews & merges PR               │                          │
         │                            │                             │                          │
         ▼                            ▼                             ▼                          │
  ┌──────────────┐             ┌──────────────┐              ┌──────────────┐                  │
  │  AttestGate  │◄────────────┤  GitHub PR   ├─────────────►│GitHub Actions│                  │
  │ Control Plane│  PR Webhook │    #14       │ Trigger CI   │• Build Image │                  │
  └──────┬───────┘             └──────────────┘              │• Cosign Sign │                  │
         │                                                   │• Syft SBOM   │                  │
         │                                                   └──────┬───────┘                  │
         │ 4. Syncs PR metadata & expected commit SHA               │                          │
         │                                                          ▼                          ▼
         │                                                   ┌──────────────┐          ┌──────────────┐
         │                                                   │  Docker Hub  │          │  Kubernetes  │
         │                                                   │   Registry   │          │Production Env│
         │                                                   └──────┬───────┘          └──────┬───────┘
         │                                                          │                         │
         │                      5. Pre-deployment Verification Gate │                         │
         └──────────────────────────────────────────────────────────┼─────────────────────────┘
                                                                    │
                                                 6. Image verification request
                                                    via Secure Tunnel Agent
                                                 7. Verdict: ALLOW (Deploy) or REJECT (Drop)
```

### The 4 Actors:
1. **Product / Security Lead:** Sets up the workspace, invites team developers, connects the organization's GitHub repositories, and defines cluster admission policies (e.g., *Strict Cosign*, *SBOM Required*, *Branch Lock*).
2. **Developers:** Work natively within GitHub. When a developer opens a Pull Request (PR), AttestGate registers the PR, the author, and the target branch.
3. **CI Attestation Pipeline (GitHub Actions):** Upon PR merge to `main`, GitHub Actions builds the image, generates an SPDX SBOM with `syft`, signs the image digest keylessly with `cosign` using GitHub OIDC, and sends the attestation receipt to AttestGate.
4. **Target Cluster Gatekeeper (Kubernetes / Docker Agent):** Connected to AttestGate via a secure, authenticated mutual tunnel. Before any pod or container starts, the agent queries AttestGate to confirm that the image digest originates from a signed, approved GitHub PR.

---

## 3. High-Level Component Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ATTESTGATE PLATFORM                                    │
│                                                                                          │
│  ┌───────────────────────┐   ┌──────────────────────────┐   ┌─────────────────────────┐  │
│  │ Team & Workspace Mgmt │   │  GitHub PR & Event Sync  │   │ Policy & Rules Engine   │  │
│  │ • Lead / Developer RBAC│   │ • Webhook Ingestion      │   │ • Enforce Sigstore/Cosign│  │
│  │ • Connected Repos     │   │ • Commit SHA Pinning     │   │ • Require SPDX SBOM     │  │
│  └───────────────────────┘   └──────────────────────────┘   └─────────────────────────┘  │
│                                            │                                             │
│                                            ▼                                             │
│                              ┌───────────────────────────┐                               │
│                              │ Cryptographic Verifier    │                               │
│                              │ • Signature Validation    │                               │
│                              │ • Syft Package Inspector  │                               │
│                              │ • Image Digest Matcher    │                               │
│                              └─────────────┬─────────────┘                               │
└────────────────────────────────────────────┼─────────────────────────────────────────────┘
                                             │
                       WebSocket / Mutual TLS Secure Tunnel
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ Production Cluster Agent  │
                               │  (Kubernetes / Docker)    │
                               │ • Intercepts Deployments  │
                               │ • Drops Malicious Pods    │
                               │ • Deploys Approved Images │
                               └───────────────────────────┘
```

---

## 4. The 3 Lifecycles

### Lifecycle A — Normal Approved Deployment
1. Developer opens **PR #14** (`feat: payment gateway`) in `OP-Prajwal/buildserver`.
2. PR is reviewed, approved, and merged into `main`.
3. GitHub Actions triggers `protected.yml`:
   - Builds container image.
   - Computes unique SHA-256 digest: `sha256:4a81...`
   - Signs digest with Cosign (`cosign sign --yes`).
   - Generates SBOM (`syft ... -o spdx-json`).
   - Attests SBOM (`cosign attest ...`).
4. Webhook delivers signed bundle to AttestGate.
5. Cluster Agent checks with AttestGate:
   - ✅ HMAC Webhook Authenticated
   - ✅ Cosign Signature verified against GitHub OIDC workflow identity
   - ✅ SBOM verified (38 valid packages)
   - ✅ Actual pulled digest matches signed digest
6. **Verdict: DEPLOYED.** Container is rolled out to production.

---

### Lifecycle B — The Supply Chain Attack (Registry Tampering)
1. An attacker compromises Docker Hub credentials or man-in-the-middles an artifact mirror.
2. Attacker runs `attacker/hack.js`, injecting a backdoor/exfiltration script into the container.
3. Attacker pushes the malicious container to Docker Hub, **overwriting the `:latest` tag**.
4. The deployment engine is instructed to deploy `:latest`.
5. **The Unprotected World (Without AttestGate):**
   - Cluster pulls `:latest`.
   - Cluster executes malware. No alerts triggered. Production is compromised.
6. **The Protected World (With AttestGate Gatekeeper):**
   - Cluster Agent intercepts the deploy request.
   - Agent requests verification from AttestGate for the incoming image hash.
   - Verification fails:
     - ❌ **No valid cryptographic signature found from GitHub CI.**
     - ❌ **Digest mismatch: Image does not match the merged PR.**
   - **Verdict: REJECTED.** Pod launch aborted immediately, incident logged, real-time alert broadcast.

---

## 5. Security & Cryptographic Guarantees

| Security Layer | Threat Addressed | Mechanism |
|---|---|---|
| **PR & Author Origin** | Rogue commits / unreviewed code | Correlates build SHA with approved GitHub Pull Request. |
| **Cosign / Sigstore OIDC** | Stolen build credentials / Fake builds | Keyless signing tied to GitHub Actions OIDC identity token (`id-token: write`). |
| **SPDX SBOM Attestation** | Hidden backdoor dependencies / CVEs | Syft package analysis cryptographically attested via Cosign. |
| **Digest Pinning** | Registry tag hijacking (`:latest` overwrite) | Deployment strictly uses immutable SHA-256 digests (`image@sha256:...`). |
| **Secure Tunnel Agent** | Unauthorized cluster deployments | Mutual authentication token between Cluster Agent and AttestGate Server. |

---

## 6. Product Packaging & Implementation Roadmap

1. **GitHub App / Marketplace Action:** One-line addition to `.github/workflows/deploy.yml`.
2. **Central AttestGate Control Plane:** Web app providing unified visibility across Repositories, PRs, Clusters, and Policies.
3. **Agent Daemon:** Lightweight binary/container for Kubernetes (Admission Webhook) or Docker VM (`systemd` daemon).
