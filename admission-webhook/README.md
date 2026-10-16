# Kubernetes admission controller

This validating webhook checks Pods and common workload templates before Kubernetes accepts them. In the project flow, it sends each image reference and workload context to the AttestGate control plane using a cluster-scoped token. The control plane allows only exact image digests that a configured CI integration has verified. The webhook fails closed if the control plane is unavailable or rejects the image.

Enforcement is opt-in per namespace with `attestgate.io/enforce=true`. Test the webhook with a non-production namespace before enabling enforcement on production workloads.

## Build and install

Build from the repository root because the image includes the shared Cosign verifier:

```sh
docker build -f admission-webhook/Dockerfile -t ghcr.io/acme/attestgate-admission:v0.1.0 .
docker push ghcr.io/acme/attestgate-admission:v0.1.0
docker image inspect ghcr.io/acme/attestgate-admission:v0.1.0 --format '{{index .RepoDigests 0}}'
```

Use the resulting immutable digest in the Deployment image field. Before applying the manifest:

1. Set `CONTROL_PLANE_URL` to the control plane's HTTPS URL, reachable from cluster nodes/pods.
2. Create namespace `attestgate-system` and the token Secret `attestgate-cluster-auth` using the one-time credential generated in the project's Kubernetes tab.
3. Create TLS secret `attestgate-admission-tls` with a certificate valid for `attestgate-admission.attestgate-system.svc`.
4. Replace the image and `caBundle` placeholders in `kubernetes.yaml` with the controller image digest and base64-encoded CA certificate.
5. Apply the manifest and wait for both replicas to become ready.

```sh
kubectl create namespace attestgate-system
kubectl -n attestgate-system create secret generic attestgate-cluster-auth --from-literal=token='<one-time-cluster-token>'
kubectl -n attestgate-system create secret tls attestgate-admission-tls --cert=tls.crt --key=tls.key
kubectl apply -f admission-webhook/kubernetes.yaml
kubectl -n attestgate-system rollout status deployment/attestgate-admission
```

Use a trusted cluster PKI or certificate manager and put its CA in `caBundle`. Keep the webhook highly available and monitor its readiness, TLS expiry, and control-plane connectivity. The webhook configuration has `failurePolicy: Fail`, so matching workload changes are blocked during outages. After validating the path, enable it on a namespace:

```sh
kubectl label namespace production attestgate.io/enforce=true
```

All container images must be pinned to `repository@sha256:<digest>` and previously registered by the matching project's CI workflow. Revoke a cluster credential in the project UI if it is lost or exposed.

## Standalone development mode

The controller can still run without a control plane using `GITHUB_REPO`, `ALLOWED_IMAGE_PREFIXES`, `TRUSTED_BRANCH`, and `TRUSTED_WORKFLOW`. That mode is for development; project enrollment and admission audit history are available through the control-plane integration.
