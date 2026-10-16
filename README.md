# AttestGate

AttestGate connects project teams, build provenance, and Kubernetes admission. A product manager creates a project and invites engineers; an engineer connects a GitHub Actions workflow; CI registers a signed image build; and a senior engineer enrolls a cluster. The admission webhook checks that workloads use an image digest already verified by that project's CI integration.

The control plane verifies the Cosign signature, SPDX SBOM attestation, and signed provenance binding the image digest to the configured GitHub repository, branch, and commit. Kubernetes admission decisions are recorded in project activity. Namespace enforcement is opt-in with `attestgate.io/enforce=true` and fails closed.

## Start the app

See [CONTROL_PLANE.md](CONTROL_PLANE.md) for GitHub OAuth setup, local Docker Compose startup, the product workflow, and deployment requirements. See [the Kubernetes controller guide](admission-webhook/README.md) to build and install the webhook.

## Repository layout

- `control-plane/` — authenticated project app, PostgreSQL API, CI registration, and cluster enrollment.
- `admission-webhook/` — Kubernetes validating admission controller and cluster manifest.
- `.github/workflows/` — sample build workflows.
- `app/` — sample application used by workflows.
- `attacker/` — image replacement exercise retained from the original prototype.
- `build-server/` — legacy Docker deployment prototype retained separately.
- `ARCHITECTURE.md` — current components and verified workflow.
- `NEW_ARCHITECTURE.md` — broader product ideas and roadmap.
