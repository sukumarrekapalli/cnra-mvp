#!/usr/bin/env python3
"""CNRA MVP: a tiny, read-only Kubernetes deployment analyzer."""

import datetime as dt
import html
import json
import os
import ssl
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


RULES = [
    {"id": "CN-022", "name": "Readiness probe exists", "severity": "HIGH", "dimension": "Reliability", "recommendation": "Add a readinessProbe to every application container.", "check": lambda d, cs: all(c.get("readinessProbe") for c in cs)},
    {"id": "CN-023", "name": "Liveness probe exists", "severity": "HIGH", "dimension": "Reliability", "recommendation": "Add a livenessProbe so unhealthy containers can be restarted.", "check": lambda d, cs: all(c.get("livenessProbe") for c in cs)},
    {"id": "CN-024", "name": "Resource requests defined", "severity": "MEDIUM", "dimension": "Scalability", "recommendation": "Define CPU and memory requests for every container.", "check": lambda d, cs: all((c.get("resources") or {}).get("requests") for c in cs)},
    {"id": "CN-025", "name": "Resource limits defined", "severity": "MEDIUM", "dimension": "Scalability", "recommendation": "Define CPU and memory limits for every container.", "check": lambda d, cs: all((c.get("resources") or {}).get("limits") for c in cs)},
    {"id": "CN-026", "name": "Rolling update strategy", "severity": "MEDIUM", "dimension": "Reliability", "recommendation": "Use a RollingUpdate deployment strategy for zero-downtime changes.", "check": lambda d, cs: (d.get("spec", {}).get("strategy", {}).get("type", "RollingUpdate") == "RollingUpdate")},
    {"id": "CN-027", "name": "Runs as non-root", "severity": "HIGH", "dimension": "Security", "recommendation": "Set pod or container securityContext.runAsNonRoot: true.", "check": lambda d, cs: _runs_as_non_root(d, cs)},
    {"id": "CN-028", "name": "Image version is pinned", "severity": "MEDIUM", "dimension": "Security", "recommendation": "Pin images to an explicit version tag or image digest.", "check": lambda d, cs: all(_image_is_pinned(c.get("image", "")) for c in cs)},
]


def _runs_as_non_root(deployment, containers):
    pod_security = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("securityContext", {}) or {}
    if pod_security.get("runAsNonRoot") is True:
        return True
    return bool(containers) and all((c.get("securityContext") or {}).get("runAsNonRoot") is True for c in containers)


def _image_is_pinned(image):
    if "@sha256:" in image:
        return True
    image_name = image.rsplit("/", 1)[-1]
    if ":" not in image_name:
        return False
    return image_name.rsplit(":", 1)[-1].lower() not in {"latest", ""}


class KubernetesError(Exception):
    pass


class KubernetesClient:
    def __init__(self):
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        if not host or not os.path.exists(token_path):
            raise KubernetesError("in-cluster credentials were not found")
        self.base_url = f"https://{host}:{port}"
        self.token = open(token_path, "r", encoding="utf-8").read().strip()
        self.context = ssl.create_default_context(cafile=ca_path)

    def get_json(self, path):
        request = urllib.request.Request(
            self.base_url + path,
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise KubernetesError(f"Kubernetes API returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise KubernetesError("could not reach the Kubernetes API") from error

    def list_deployments(self):
        namespace = os.environ.get("CNRA_NAMESPACE", "all")
        if namespace.lower() in {"all", "*"}:
            path = "/apis/apps/v1/deployments"
        else:
            path = f"/apis/apps/v1/namespaces/{namespace}/deployments"
        return self.get_json(path).get("items", [])


def demo_deployments():
    return [
        {"metadata": {"name": "checkout-service", "namespace": "store"}, "spec": {"strategy": {"type": "RollingUpdate"}, "template": {"spec": {"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "checkout", "image": "ghcr.io/acme/checkout:v1.8.2", "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}}, "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "512Mi"}}}]}}}},
        {"metadata": {"name": "payment-service", "namespace": "store"}, "spec": {"template": {"spec": {"containers": [{"name": "payment", "image": "acme/payment:latest", "resources": {"requests": {"cpu": "100m"}}}]}}}},
        {"metadata": {"name": "catalog-api", "namespace": "store"}, "spec": {"strategy": {"type": "RollingUpdate"}, "template": {"spec": {"containers": [{"name": "catalog", "image": "acme/catalog:v2.1.0", "readinessProbe": {"tcpSocket": {"port": 8080}}, "livenessProbe": {"tcpSocket": {"port": 8080}}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "250m", "memory": "256Mi"}}, "securityContext": {"runAsNonRoot": True}}]}}}},
    ]


def build_report():
    demo_mode = os.environ.get("CNRA_DEMO_MODE", "").lower() == "true"
    try:
        if demo_mode or not os.environ.get("KUBERNETES_SERVICE_HOST"):
            deployments = demo_deployments()
            mode = "demo"
        else:
            deployments = KubernetesClient().list_deployments()
            mode = "cluster"
    except KubernetesError as error:
        return {"error": str(error), "mode": "cluster", "generatedAt": now()}

    results = []
    for deployment in deployments:
        metadata = deployment.get("metadata", {})
        spec = deployment.get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", {})
        containers = pod_spec.get("containers", [])
        deployment_name = metadata.get("name", "unnamed")
        namespace = metadata.get("namespace", "default")
        checks = []
        for rule in RULES:
            passed = bool(containers) and rule["check"](deployment, containers)
            checks.append({"id": rule["id"], "name": rule["name"], "severity": rule["severity"], "dimension": rule["dimension"], "passed": passed, "recommendation": rule["recommendation"]})
        results.append({"name": deployment_name, "namespace": namespace, "checks": checks})

    all_checks = [check for result in results for check in result["checks"]]
    passed_count = sum(1 for check in all_checks if check["passed"])
    dimensions = {}
    for check in all_checks:
        dimensions.setdefault(check["dimension"], []).append(check["passed"])
    dimension_scores = {name: round(sum(values) / len(values) * 100) for name, values in dimensions.items()}
    findings = []
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for result in results:
        for check in result["checks"]:
            if not check["passed"]:
                findings.append({**check, "resource": f"{result['namespace']}/{result['name']}"})
    findings.sort(key=lambda finding: (severity_order.get(finding["severity"], 9), finding["resource"]))
    total = len(all_checks)
    return {
        "mode": mode,
        "generatedAt": now(),
        "namespace": os.environ.get("CNRA_NAMESPACE", "all"),
        "deploymentsAnalyzed": len(results),
        "score": round(passed_count / total * 100) if total else 0,
        "dimensions": dimension_scores,
        "findings": findings,
        "services": results,
    }


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def page(report):
    score = report.get("score", "—")
    dimensions = report.get("dimensions", {})
    findings = report.get("findings", [])
    error = report.get("error")
    if error:
        content = f'<div class="error"><strong>Scan unavailable</strong><span>{html.escape(error)}</span><small>Check the ServiceAccount permissions and pod logs.</small></div>'
    elif not report.get("deploymentsAnalyzed"):
        content = '<div class="empty"><strong>No deployments found</strong><span>Set CNRA_NAMESPACE to a namespace with workloads, or keep it set to all.</span></div>'
    else:
        finding_markup = "".join(
            f'<li><span class="severity {item["severity"].lower()}">{item["severity"]}</span><div><strong>{html.escape(item["id"])} · {html.escape(item["name"])}</strong><small>{html.escape(item["resource"])}</small></div></li>'
            for item in findings[:8]
        ) or '<li class="all-good"><span>✓</span><div><strong>No rule violations found</strong><small>Nice work. Your scanned deployments passed every check.</small></div></li>'
        dimension_markup = "".join(f'<div class="metric"><span>{html.escape(name)}</span><strong>{value}</strong><i><b style="width:{value}%"></b></i></div>' for name, value in dimensions.items())
        content = f'<div class="summary"><div class="score"><small>READINESS SCORE</small><strong>{score}<em>/100</em></strong><span>{report["deploymentsAnalyzed"]} deployments analyzed</span></div><div class="metrics">{dimension_markup}</div></div><div class="findings"><div class="section-title"><span>Findings</span><small>{len(findings)} open</small></div><ul>{finding_markup}</ul></div>'
    data = html.escape(json.dumps(report))
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CNRA MVP</title>
<style>
:root{--ink:#102e2b;--muted:#71877e;--line:#d7ddd2;--paper:#f4f4ee;--orange:#f06638;--lime:#c8e974}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{max-width:980px;margin:0 auto;padding:42px 24px 60px}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:25px}.brand{font-weight:800;font-size:20px;letter-spacing:-.07em}.brand i{display:inline-block;width:8px;height:8px;margin-right:4px;border-radius:2px;background:var(--orange)}button{border:0;border-radius:4px;padding:11px 15px;background:var(--ink);color:white;cursor:pointer;font-weight:700;font-size:12px}button:hover{background:var(--orange)}.eyebrow{margin-top:70px;color:var(--orange);font:10px monospace;letter-spacing:.12em;text-transform:uppercase}.hero{display:flex;justify-content:space-between;gap:24px;align-items:end}.hero h1{max-width:610px;margin:17px 0 14px;font-size:clamp(40px,7vw,70px);letter-spacing:-.08em;line-height:.94}.hero p{max-width:480px;color:var(--muted);line-height:1.7}.meta{margin:42px 0 18px;color:var(--muted);font:10px monospace;text-transform:uppercase}.summary{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:28px}.score,.metrics,.findings{border:1px solid var(--line);background:#fffef9}.score{padding:28px}.score small,.section-title small,.metric span{color:var(--muted);font:10px monospace;letter-spacing:.08em;text-transform:uppercase}.score strong{display:block;margin:25px 0 7px;font-size:86px;letter-spacing:-.1em;line-height:.8}.score em{color:var(--muted);font:14px monospace;font-style:normal;letter-spacing:0}.score span{color:var(--muted);font-size:11px}.metrics{padding:22px 24px}.metric{margin:0 0 24px}.metric:last-child{margin-bottom:0}.metric strong{float:right;font:12px monospace}.metric i{display:block;height:6px;margin-top:10px;background:#e8eee4;border-radius:8px}.metric b{display:block;height:100%;background:var(--orange);border-radius:8px}.metric:nth-child(3n) b{background:var(--lime)}.findings{margin-top:14px;padding:22px 24px}.section-title{display:flex;justify-content:space-between;margin-bottom:16px;font-weight:800}.findings ul{padding:0;margin:0;list-style:none}.findings li{display:flex;align-items:center;gap:12px;padding:13px 0;border-top:1px solid var(--line)}.findings li div{display:flex;flex-direction:column;gap:3px}.findings li strong{font-size:12px}.findings li small{color:var(--muted);font:10px monospace}.severity{width:56px;padding:5px 4px;text-align:center;font:9px monospace;border-radius:2px;background:#f9d3c5;color:#a33e21}.severity.medium{background:#f4e6af;color:#816d19}.all-good>span{width:24px;height:24px;display:grid;place-items:center;background:var(--lime);border-radius:50%}.error,.empty{display:flex;flex-direction:column;gap:10px;margin-top:28px;padding:22px;background:#fffef9;border:1px solid var(--line)}.error strong{color:var(--orange)}.error span,.empty span{color:var(--muted)}.error small{font:10px monospace;color:var(--muted)}footer{margin-top:20px;color:var(--muted);font:10px monospace}@media(max-width:650px){.hero{display:block}.summary{grid-template-columns:1fr}.hero h1{font-size:49px}.shell{padding-top:24px}.eyebrow{margin-top:45px}}
</style></head><body><main class="shell"><header class="top"><div class="brand"><i></i>CNRA <span style="color:#71877e;font-size:10px;letter-spacing:0">/ MVP</span></div><button onclick="location.reload()">Run scan ↗</button></header><div class="eyebrow">Cloud native readiness analyzer</div><section class="hero"><div><h1>How ready is your cluster?</h1><p>A tiny, read-only scan of your Kubernetes Deployments against seven high-signal cloud-native rules.</p></div></section><div class="meta">MODE: __MODE__ · NAMESPACE: __NAMESPACE__ · GENERATED: __TIME__</div>__CONTENT__<footer>CNRA MVP · Read-only access · <a href="/healthz" style="color:#f06638">healthz</a></footer></main></body></html>""".replace("__MODE__", html.escape(report.get("mode", "unknown"))).replace("__NAMESPACE__", html.escape(str(report.get("namespace", "—")))).replace("__TIME__", html.escape(report.get("generatedAt", "—"))).replace("__CONTENT__", content)


class Handler(BaseHTTPRequestHandler):
    def send_body(self, body, content_type="text/html; charset=utf-8", status=200):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_body("ok\n", "text/plain; charset=utf-8")
        elif self.path == "/api/assessment":
            self.send_body(json.dumps(build_report()), "application/json")
        else:
            self.send_body(page(build_report()))

    def do_POST(self):
        if self.path == "/api/assessment":
            self.send_body(json.dumps(build_report()), "application/json")
        else:
            self.send_body("not found\n", "text/plain; charset=utf-8", 404)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"CNRA MVP listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
