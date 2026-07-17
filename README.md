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
- CN-029 through CN-048 workload security, scheduling, lifecycle, labeling, and rollout baselines

The result is a 0–100 score, dimension scores, expandable evidence-backed findings, and a full rule catalog. It stores nothing and has no write permissions.

## Install with Helm

The chart is versioned at `0.2.3` and lives in `chart/cnra-mvp`.
The container image is published separately as `sukumar9/cnra-mvp-image:0.2.3`:

```bash
docker buildx build --no-cache --platform linux/amd64 \
  -t sukumar9/cnra-mvp-image:0.2.3 --push ./cnra-mvp

helm package cnra-mvp/chart/cnra-mvp
helm registry login registry-1.docker.io -u sukumar9
helm push cnra-mvp-0.2.3.tgz oci://registry-1.docker.io/sukumar9
```

```bash
helm upgrade --install cnra ./cnra-mvp/chart/cnra-mvp \
  --namespace cnra-system \
  --create-namespace \
  --set image.repository=sukumar9/cnra-mvp-image \
  --set image.tag=0.2.2
```

To scan one namespace instead of the whole cluster:

```bash
helm upgrade cnra ./cnra-mvp/chart/cnra-mvp \
  --namespace cnra-system \
  --set scan.namespace=my-namespace
```

Open the dashboard through the in-cluster Service:

```bash
kubectl -n cnra-system port-forward svc/cnra-cnra-mvp 8080:80
```

The chart grants only `get`, `list`, and `watch` on `deployments.apps`.

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
