# Run the AttestGate control plane

This MVP is a single control-plane service backed by PostgreSQL. It uses GitHub OAuth for team identity; it does not request repository access. CI authenticates with a project integration token, and each Kubernetes cluster uses its own revocable token.

## Start locally

1. Create a GitHub OAuth App. Set its homepage to `http://localhost:4100` and its authorization callback to `http://localhost:4100/auth/github/callback`. The app requests `read:user` and `user:email` so invitations can be restricted to the invited account's verified primary email.
2. Copy `.env.example` to `.env`. Set `POSTGRES_PASSWORD` to a long random alphanumeric value, then fill in the OAuth client ID and secret. Local defaults use HTTP and `COOKIE_SECURE=false`.
3. Start the app with `docker compose up --build -d`, then open `http://localhost:4100` and sign in with GitHub.

For a public deployment, set `APP_BASE_URL` to the public HTTPS URL, set `COOKIE_SECURE=true`, and set the OAuth callback to `<APP_BASE_URL>/auth/github/callback`. Put TLS termination and access logging in front of the service. The application rejects non-local HTTP URLs.

## Host the control plane with Neon

Create a Neon project in a region near the control-plane host. In Neon’s connection details, choose the pooled connection string and use the URI containing `sslmode=require`; keep it private. The pooled endpoint is intended for applications with multiple concurrent connections. [Neon connection pooling](https://neon.com/docs/connect/connection-pooling) and [node-postgres SSL configuration](https://node-postgres.com/features/ssl) document these options.

Copy `.env.neon.example` to `.env.neon` and fill in the pooled `DATABASE_URL`, public `APP_BASE_URL`, and GitHub OAuth credentials. Add the public callback URL `<APP_BASE_URL>/auth/github/callback` to the OAuth App. On the Linux host, run:

```sh
docker compose --env-file .env.neon -f docker-compose.neon.yml up --build -d
```

This deployment file omits the bundled local PostgreSQL service and binds the control plane to host loopback on port 4100. Configure the host’s HTTPS reverse proxy to forward to `127.0.0.1:4100`, and allow public inbound traffic only to the proxy’s HTTP/HTTPS ports. Check `https://<your-domain>/healthz` after the proxy and DNS are configured. `.env.neon` is git-ignored; do not commit or share it.

## Product workflow

1. Create a project. The creator becomes its owner.
2. In **Team**, invite engineers by their verified GitHub email. Send the one-time URL to each person. Invitations expire after seven days; the app currently shows a copyable link and does not send email.
3. In **CI integration**, register the exact GitHub repository, workflow file, protected branch, and image repository. Save the one-time token as the repository's `ATTESTGATE_TOKEN` GitHub Actions secret. Keep the workflow and target branch protected.
4. Add the generated workflow snippet after the image has been pushed and signed and its SPDX SBOM attestation has been published. The snippet assumes the image push step has ID `push` and exposes `steps.push.outputs.digest`. Give the job `id-token: write` and the image publishing permissions it needs. Its Cosign provenance statement binds the image digest to the repository, branch, and commit; registration rejects missing or mismatched signature, SBOM, or provenance evidence.
5. In **Kubernetes**, create a cluster credential and copy the token immediately. Create the `attestgate-cluster-auth` Secret in `attestgate-system`; configure the admission controller with the control plane's reachable HTTPS URL and this secret. Install a trusted webhook TLS certificate, set the webhook CA bundle and controller image digest, then apply `admission-webhook/kubernetes.yaml`.
6. Confirm the webhook and control plane are reachable before labeling a namespace `attestgate.io/enforce=true`. Deployments must use image references pinned to the exact SHA-256 digest.

The cluster token is shown only once; revoke and recreate it if lost. CI tokens can be disabled and cluster tokens revoked from their project tabs. Audit records show verified builds and admission allow/deny decisions.

## Current boundaries

This is a functional initial product path, not a hosted multi-tenant service. It has no email delivery, GitHub App installation, PR approval checks, policy editor, SBOM vulnerability thresholds, billing, or automated Kubernetes certificate management. The compose setup is a single control-plane instance; use a managed PostgreSQL service, backups, HTTPS, secret management, monitoring, and capacity planning for production operations. Do not expose the local development configuration to the public internet.
