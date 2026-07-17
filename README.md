# CNRA MVP

This is a deliberately small, read-only Cloud Native Readiness Analyzer demo.

It scans Kubernetes `Deployments` and evaluates seven rules:

- CN-022 readiness probe
- CN-023 liveness probe
- CN-024 resource requests
- CN-025 resource limits
- CN-026 rolling update strategy
- CN-027 non-root execution
- CN-028 pinned container image

The result is a 0–100 score, dimension scores, and evidence-backed findings. It stores nothing and has no write permissions.

## Run it in a cluster

Build and push the tiny image to a registry your cluster can pull from:

```bash
docker build -t YOUR_REGISTRY/cnra-mvp:0.1.0 ./cnra-mvp
docker push YOUR_REGISTRY/cnra-mvp:0.1.0
```

Replace `YOUR_REGISTRY/cnra-mvp:0.1.0` in `deploy.yaml`, then install:

```bash
kubectl apply -f cnra-mvp/deploy.yaml
kubectl -n cnra-system port-forward svc/cnra-mvp 8080:80
```

Open [http://localhost:8080](http://localhost:8080). Change `CNRA_NAMESPACE` from `all` to a single namespace if you want to scope the scan.

## Local preview

Without Kubernetes credentials, the service automatically shows three demo Deployments:

```bash
CNRA_DEMO_MODE=true python cnra-mvp/app.py
```

The only Kubernetes permission granted by the manifest is `get`, `list`, and `watch` on `deployments.apps`.
