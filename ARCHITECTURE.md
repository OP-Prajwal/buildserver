# AttestGate architecture

AttestGate has a project control plane and a Kubernetes admission webhook.

```text
Product manager creates project and invites engineers
    -> project members create a GitHub Actions integration
    -> CI pushes an image, signs it, and publishes SPDX SBOM plus signed provenance
    -> control plane verifies signature, SBOM, provenance, source repo, branch, commit, and digest
    -> senior engineer enrolls a Kubernetes cluster
    -> admission webhook asks the control plane about each digest-pinned workload image
    -> allow or deny is recorded in project activity
```

## Components

- `control-plane/` serves the browser app and API, GitHub OAuth, project roles and invites, CI registrations, cluster tokens, and audit history. PostgreSQL stores durable state. CI and cluster credentials are stored as SHA-256 hashes.
- `build-server/verifier.js` verifies Cosign image signatures and SPDX and custom provenance attestations against the configured GitHub Actions OIDC identity.
- `admission-webhook/` is a Kubernetes validating webhook. It checks pods and common workload templates, requires `@sha256:` image references, and queries the control plane. It fails closed on timeouts or rejected decisions.
- `docker-compose.yml` runs the control plane and PostgreSQL for a single-instance deployment.

The webhook only enforces namespaces labeled `attestgate.io/enforce=true`. Its Kubernetes webhook uses `failurePolicy: Fail`; keep the webhook and control plane available before enabling enforcement. The current policy approves an image once its CI workflow has registered and verified it. PR review state, vulnerability thresholds, policy editing, multi-tenant billing, and automated secret delivery are not implemented.

See [CONTROL_PLANE.md](CONTROL_PLANE.md) to configure and run the application, and [admission-webhook/README.md](admission-webhook/README.md) to install Kubernetes enforcement. `NEW_ARCHITECTURE.md` retains broader future product ideas.
