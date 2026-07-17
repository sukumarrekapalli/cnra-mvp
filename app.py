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


def _pod_spec(deployment):
    return deployment.get("spec", {}).get("template", {}).get("spec", {}) or {}


def _containers(deployment):
    return _pod_spec(deployment).get("containers", []) or []


def _all_containers(containers, predicate):
    return bool(containers) and all(predicate(container) for container in containers)


def _has_cpu_and_memory(container, bucket):
    values = (container.get("resources") or {}).get(bucket, {}) or {}
    return bool(values.get("cpu") and values.get("memory"))


def _security_context(deployment):
    return _pod_spec(deployment).get("securityContext", {}) or {}


def _all_container_security(containers, key, value=True):
    return _all_containers(containers, lambda c: (c.get("securityContext") or {}).get(key) is value)


def _has_capability_drop_all(containers):
    def check(container):
        drops = ((container.get("securityContext") or {}).get("capabilities") or {}).get("drop", []) or []
        return "ALL" in drops
    return _all_containers(containers, check)


def _probe_timeout_configured(containers):
    def check(container):
        return all((container.get(probe) or {}).get("timeoutSeconds") for probe in ("readinessProbe", "livenessProbe"))
    return _all_containers(containers, check)


RULES = [
    {"id": "CN-022", "name": "Readiness probe exists", "severity": "HIGH", "dimension": "Reliability", "path": "spec.template.spec.containers[*].readinessProbe", "why": "Without readiness checks, traffic can be sent to a container before it is ready.", "recommendation": "Add an HTTP, TCP, or exec readinessProbe that represents real application readiness.", "standard": "Kubernetes health checks", "check": lambda d, cs: _all_containers(cs, lambda c: bool(c.get("readinessProbe")))},
    {"id": "CN-023", "name": "Liveness probe exists", "severity": "HIGH", "dimension": "Reliability", "path": "spec.template.spec.containers[*].livenessProbe", "why": "A stuck process can remain in service indefinitely when Kubernetes has no liveness signal.", "recommendation": "Add a livenessProbe that detects a wedged process without depending on downstream services.", "standard": "Kubernetes health checks", "check": lambda d, cs: _all_containers(cs, lambda c: bool(c.get("livenessProbe")))},
    {"id": "CN-024", "name": "CPU and memory requests", "severity": "MEDIUM", "dimension": "Scalability", "path": "spec.template.spec.containers[*].resources.requests", "why": "Requests help the scheduler place workloads and make capacity planning meaningful.", "recommendation": "Set both cpu and memory requests for each application container.", "standard": "Kubernetes scheduling baseline", "check": lambda d, cs: _all_containers(cs, lambda c: _has_cpu_and_memory(c, "requests"))},
    {"id": "CN-025", "name": "CPU and memory limits", "severity": "MEDIUM", "dimension": "Scalability", "path": "spec.template.spec.containers[*].resources.limits", "why": "Limits reduce noisy-neighbor risk and make resource behavior predictable.", "recommendation": "Set CPU and memory limits based on observed workload behavior.", "standard": "Kubernetes resource management", "check": lambda d, cs: _all_containers(cs, lambda c: _has_cpu_and_memory(c, "limits"))},
    {"id": "CN-026", "name": "Rolling update strategy", "severity": "MEDIUM", "dimension": "Reliability", "path": "spec.strategy.type", "why": "Recreate deployments can create avoidable downtime during normal releases.", "recommendation": "Use strategy.type: RollingUpdate unless the workload explicitly requires replacement.", "standard": "Kubernetes Deployment strategy", "check": lambda d, cs: d.get("spec", {}).get("strategy", {}).get("type", "RollingUpdate") == "RollingUpdate"},
    {"id": "CN-027", "name": "Runs as non-root", "severity": "HIGH", "dimension": "Security", "path": "spec.template.spec.securityContext.runAsNonRoot", "why": "A compromised process has more leverage when it runs as root inside the container.", "recommendation": "Set pod or container securityContext.runAsNonRoot: true and verify the image supports it.", "standard": "Pod Security restricted baseline", "check": lambda d, cs: _security_context(d).get("runAsNonRoot") is True or _all_container_security(cs, "runAsNonRoot")},
    {"id": "CN-028", "name": "Image version is pinned", "severity": "MEDIUM", "dimension": "Security", "path": "spec.template.spec.containers[*].image", "why": "Mutable tags make rollbacks and audit trails unreliable.", "recommendation": "Use an immutable version tag or a sha256 image digest instead of latest.", "standard": "Supply-chain hygiene", "check": lambda d, cs: _all_containers(cs, lambda c: _image_is_pinned(c.get("image", "")))},
    {"id": "CN-029", "name": "Privilege escalation disabled", "severity": "HIGH", "dimension": "Security", "path": "spec.template.spec.containers[*].securityContext.allowPrivilegeEscalation", "why": "Allowing privilege escalation can turn an application exploit into a broader container compromise.", "recommendation": "Set allowPrivilegeEscalation: false on every application container.", "standard": "Pod Security restricted baseline", "check": lambda d, cs: _all_container_security(cs, "allowPrivilegeEscalation", False)},
    {"id": "CN-030", "name": "Root filesystem is read-only", "severity": "MEDIUM", "dimension": "Security", "path": "spec.template.spec.containers[*].securityContext.readOnlyRootFilesystem", "why": "A read-only filesystem limits persistence and tampering after a process compromise.", "recommendation": "Set readOnlyRootFilesystem: true and mount writable emptyDir volumes only where needed.", "standard": "Container hardening baseline", "check": lambda d, cs: _all_container_security(cs, "readOnlyRootFilesystem")},
    {"id": "CN-031", "name": "Linux capabilities dropped", "severity": "HIGH", "dimension": "Security", "path": "spec.template.spec.containers[*].securityContext.capabilities.drop", "why": "Unused Linux capabilities increase the kernel-level attack surface.", "recommendation": "Drop ALL capabilities and add back only a narrowly justified capability.", "standard": "Pod Security restricted baseline", "check": lambda d, cs: _has_capability_drop_all(cs)},
    {"id": "CN-032", "name": "RuntimeDefault seccomp profile", "severity": "HIGH", "dimension": "Security", "path": "spec.template.spec.securityContext.seccompProfile.type", "why": "Seccomp reduces the system calls available to a compromised container.", "recommendation": "Set pod securityContext.seccompProfile.type: RuntimeDefault.", "standard": "Pod Security restricted baseline", "check": lambda d, cs: _security_context(d).get("seccompProfile", {}).get("type") == "RuntimeDefault"},
    {"id": "CN-033", "name": "Image pull policy is explicit", "severity": "LOW", "dimension": "Operations", "path": "spec.template.spec.containers[*].imagePullPolicy", "why": "An explicit policy prevents deployment behavior from changing silently with image naming conventions.", "recommendation": "Set imagePullPolicy explicitly, usually IfNotPresent for pinned images.", "standard": "Deployment reproducibility", "check": lambda d, cs: _all_containers(cs, lambda c: c.get("imagePullPolicy") in {"IfNotPresent", "Always", "Never"})},
    {"id": "CN-034", "name": "Multiple replicas configured", "severity": "LOW", "dimension": "Reliability", "path": "spec.replicas", "why": "A single replica creates a single point of failure during restarts, upgrades, and node maintenance.", "recommendation": "Run at least two replicas where the workload supports it.", "standard": "High availability baseline", "check": lambda d, cs: int(d.get("spec", {}).get("replicas", 1) or 1) >= 2},
    {"id": "CN-035", "name": "Graceful termination configured", "severity": "LOW", "dimension": "Reliability", "path": "spec.template.spec.terminationGracePeriodSeconds", "why": "Graceful termination gives the application time to finish in-flight work and close connections.", "recommendation": "Set an intentional terminationGracePeriodSeconds greater than zero.", "standard": "Kubernetes lifecycle baseline", "check": lambda d, cs: int(_pod_spec(d).get("terminationGracePeriodSeconds", 0) or 0) > 0},
    {"id": "CN-036", "name": "Pod anti-affinity configured", "severity": "LOW", "dimension": "Reliability", "path": "spec.template.spec.affinity.podAntiAffinity", "why": "Without placement guidance, replicas may land on the same failure domain.", "recommendation": "Add preferred or required podAntiAffinity for replicas of critical services.", "standard": "Resilient scheduling baseline", "check": lambda d, cs: bool((_pod_spec(d).get("affinity") or {}).get("podAntiAffinity"))},
    {"id": "CN-037", "name": "Topology spread configured", "severity": "LOW", "dimension": "Reliability", "path": "spec.template.spec.topologySpreadConstraints", "why": "Topology spread helps distribute replicas across nodes or zones.", "recommendation": "Add topologySpreadConstraints for critical, replicated workloads.", "standard": "Resilient scheduling baseline", "check": lambda d, cs: bool(_pod_spec(d).get("topologySpreadConstraints"))},
    {"id": "CN-038", "name": "Service account is explicit", "severity": "LOW", "dimension": "Security", "path": "spec.template.spec.serviceAccountName", "why": "An explicit identity makes workload permissions reviewable and avoids accidental use of the default account.", "recommendation": "Create a dedicated ServiceAccount and reference it with serviceAccountName.", "standard": "Kubernetes identity baseline", "check": lambda d, cs: bool(_pod_spec(d).get("serviceAccountName"))},
    {"id": "CN-039", "name": "Service token automount reviewed", "severity": "MEDIUM", "dimension": "Security", "path": "spec.template.spec.automountServiceAccountToken", "why": "An unused service-account token is unnecessary credential material inside the pod.", "recommendation": "Set automountServiceAccountToken: false unless the application calls the Kubernetes API.", "standard": "Least-privilege baseline", "check": lambda d, cs: _pod_spec(d).get("automountServiceAccountToken") is False},
    {"id": "CN-040", "name": "Host network disabled", "severity": "HIGH", "dimension": "Security", "path": "spec.template.spec.hostNetwork", "why": "Host networking bypasses normal pod network isolation.", "recommendation": "Keep hostNetwork unset or false unless the workload has a documented node-level requirement.", "standard": "Pod Security baseline", "check": lambda d, cs: _pod_spec(d).get("hostNetwork") is not True},
    {"id": "CN-041", "name": "Host PID and IPC disabled", "severity": "HIGH", "dimension": "Security", "path": "spec.template.spec.hostPID / hostIPC", "why": "Sharing host process or IPC namespaces exposes additional node-level information and control.", "recommendation": "Keep hostPID and hostIPC false unless the workload has a documented exception.", "standard": "Pod Security baseline", "check": lambda d, cs: _pod_spec(d).get("hostPID") is not True and _pod_spec(d).get("hostIPC") is not True},
    {"id": "CN-042", "name": "No hostPath volume", "severity": "HIGH", "dimension": "Security", "path": "spec.template.spec.volumes[*].hostPath", "why": "HostPath mounts can expose the node filesystem to the workload.", "recommendation": "Use ConfigMaps, Secrets, PVCs, or emptyDir instead of hostPath where possible.", "standard": "Pod Security baseline", "check": lambda d, cs: not any(volume.get("hostPath") for volume in _pod_spec(d).get("volumes", []) or [])},
    {"id": "CN-043", "name": "Application labels present", "severity": "LOW", "dimension": "Operations", "path": "metadata.labels.app / spec.template.metadata.labels.app", "why": "Consistent labels improve ownership, filtering, service discovery, and dashboard queries.", "recommendation": "Add a stable app label to both the Deployment and its pod template.", "standard": "Kubernetes labeling convention", "check": lambda d, cs: bool((d.get("metadata", {}).get("labels") or {}).get("app")) and bool((d.get("spec", {}).get("template", {}).get("metadata", {}).get("labels") or {}).get("app"))},
    {"id": "CN-044", "name": "Probe timeouts configured", "severity": "LOW", "dimension": "Reliability", "path": "spec.template.spec.containers[*].readinessProbe.timeoutSeconds / livenessProbe.timeoutSeconds", "why": "Explicit timeouts keep health checks from hanging longer than intended.", "recommendation": "Set a small, explicit timeoutSeconds on both readiness and liveness probes.", "standard": "Kubernetes health checks", "check": lambda d, cs: _probe_timeout_configured(cs)},
    {"id": "CN-045", "name": "Revision history is bounded", "severity": "LOW", "dimension": "Operations", "path": "spec.revisionHistoryLimit", "why": "Unbounded ReplicaSet history creates unnecessary control-plane objects over time.", "recommendation": "Set revisionHistoryLimit to a deliberate value such as 5 or 10.", "standard": "Kubernetes operations baseline", "check": lambda d, cs: isinstance(d.get("spec", {}).get("revisionHistoryLimit"), int) and d.get("spec", {}).get("revisionHistoryLimit") >= 1},
    {"id": "CN-046", "name": "Rolling update limits explicit", "severity": "LOW", "dimension": "Reliability", "path": "spec.strategy.rollingUpdate.maxUnavailable / maxSurge", "why": "Explicit rollout limits make availability and capacity behavior predictable during releases.", "recommendation": "Set maxUnavailable and maxSurge intentionally for the workload.", "standard": "Kubernetes Deployment strategy", "check": lambda d, cs: d.get("spec", {}).get("strategy", {}).get("type", "RollingUpdate") != "RollingUpdate" or bool(d.get("spec", {}).get("strategy", {}).get("rollingUpdate", {}).get("maxUnavailable")) and bool(d.get("spec", {}).get("strategy", {}).get("rollingUpdate", {}).get("maxSurge"))},
    {"id": "CN-047", "name": "Selector and pod labels align", "severity": "MEDIUM", "dimension": "Operations", "path": "spec.selector.matchLabels", "why": "A clear selector-to-template match prevents orphaned pods and makes ownership unambiguous.", "recommendation": "Ensure every selector matchLabel is present with the same value on template.metadata.labels.", "standard": "Kubernetes Deployment contract", "check": lambda d, cs: all((d.get("spec", {}).get("template", {}).get("metadata", {}).get("labels") or {}).get(key) == value for key, value in (d.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}).items())},
    {"id": "CN-048", "name": "Container ports declared", "severity": "LOW", "dimension": "Operations", "path": "spec.template.spec.containers[*].ports", "why": "Declared ports make workload intent discoverable to operators and tooling.", "recommendation": "Declare the application ports exposed by each container.", "standard": "Kubernetes workload metadata", "check": lambda d, cs: _all_containers(cs, lambda c: bool(c.get("ports")))},
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


def _rule_metadata(rule):
    return {key: value for key, value in rule.items() if key != "check"}


def _evidence(rule, deployment, containers):
    names = [container.get("name", "unnamed-container") for container in containers]
    if rule["id"] in {"CN-022", "CN-023", "CN-024", "CN-025", "CN-028", "CN-029", "CN-030", "CN-031", "CN-033", "CN-044", "CN-048"}:
        return f"{rule['path']} is not satisfied for one or more containers: {', '.join(names)}."
    if rule["id"] == "CN-042":
        paths = [volume.get("hostPath", {}).get("path", "unknown") for volume in _pod_spec(deployment).get("volumes", []) or [] if volume.get("hostPath")]
        return f"hostPath volume(s) found: {', '.join(paths)}."
    if rule["id"] == "CN-047":
        return "One or more selector matchLabels are missing from template.metadata.labels."
    return f"{rule['path']} is missing or does not meet the rule baseline."


def _catalog(results=None):
    results = results or []
    checks_by_rule = {rule["id"]: [] for rule in RULES}
    for result in results:
        for check in result["checks"]:
            checks_by_rule[check["id"]].append(check["passed"])
    catalog = []
    for rule in RULES:
        values = checks_by_rule[rule["id"]]
        catalog.append({**_rule_metadata(rule), "deployments": len(values), "passed": sum(values), "failed": len(values) - sum(values), "status": "PASS" if values and all(values) else "OPEN" if values else "NOT_EVALUATED"})
    return catalog


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
        return {"error": str(error), "mode": "cluster", "generatedAt": now(), "ruleCatalog": _catalog()}

    results = []
    for deployment in deployments:
        metadata = deployment.get("metadata", {})
        spec = deployment.get("spec", {})
        containers = _containers(deployment)
        deployment_name = metadata.get("name", "unnamed")
        namespace = metadata.get("namespace", "default")
        checks = []
        for rule in RULES:
            passed = bool(containers) and rule["check"](deployment, containers)
            checks.append({**_rule_metadata(rule), "passed": passed, "evidence": _evidence(rule, deployment, containers) if not passed else f"{rule['path']} satisfied for {len(containers)} container(s)."})
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
                findings.append({**check, "resource": f"{result['namespace']}/{result['name']}", "nextStep": check["recommendation"]})
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
        "ruleCatalog": _catalog(results),
    }


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def page(report):
    score = report.get("score", "—")
    dimensions = report.get("dimensions", {})
    findings = report.get("findings", [])
    catalog = report.get("ruleCatalog", _catalog())
    error = report.get("error")
    if error:
        content = f'<div class="error"><strong>Scan unavailable</strong><span>{html.escape(error)}</span><small>Check the ServiceAccount permissions and pod logs.</small></div>'
    elif not report.get("deploymentsAnalyzed"):
        content = '<div class="empty"><strong>No deployments found</strong><span>Set CNRA_NAMESPACE to a namespace with workloads, or keep it set to all.</span></div>'
    else:
        finding_markup = "".join(
            f'<li><details class="finding"><summary><span class="severity {item["severity"].lower()}">{item["severity"]}</span><div><strong>{html.escape(item["id"])} · {html.escape(item["name"])}</strong><small>{html.escape(item["resource"])}</small></div><b class="expand">+</b></summary><div class="finding-detail"><div><label>Why it matters</label><p>{html.escape(item["why"])}</p></div><div><label>Evidence</label><p class="evidence">{html.escape(item["evidence"])}</p><code>{html.escape(item["path"])}</code></div><div><label>Recommended remediation</label><p>{html.escape(item["recommendation"])}</p></div><div><label>Baseline</label><p>{html.escape(item["standard"])}</p></div></div></details></li>'
            for item in findings[:20]
        ) or '<li class="all-good"><span>✓</span><div><strong>No rule violations found</strong><small>Nice work. Your scanned deployments passed every check.</small></div></li>'
        dimension_markup = "".join(f'<div class="metric"><span>{html.escape(name)}</span><strong>{value}</strong><i><b style="width:{value}%"></b></i></div>' for name, value in dimensions.items())
        high = sum(1 for finding in findings if finding["severity"] == "HIGH")
        medium = sum(1 for finding in findings if finding["severity"] == "MEDIUM")
        low = sum(1 for finding in findings if finding["severity"] == "LOW")
        more = f'<p class="more-note">Showing the first 20 of {len(findings)} findings. Use the rule catalog below to review every check.</p>' if len(findings) > 20 else ""
        content = f'<div class="summary"><div class="score"><small>READINESS SCORE</small><strong>{score}<em>/100</em></strong><span>{report["deploymentsAnalyzed"]} deployments analyzed</span></div><div class="metrics">{dimension_markup}<div class="severity-counts"><span><b class="dot high"></b>{high} high</span><span><b class="dot medium"></b>{medium} medium</span><span><b class="dot low"></b>{low} low</span></div></div></div><div class="findings"><div class="section-title"><span>Findings <small class="hint">click any row to expand</small></span><small>{len(findings)} open</small></div><ul>{finding_markup}</ul>{more}</div>'
    catalog_markup = "".join(
        f'<details class="catalog-row"><summary><span class="catalog-status {item["status"].lower()}">{item["status"]}</span><div><strong>{html.escape(item["id"])} · {html.escape(item["name"])}</strong><small>{html.escape(item["dimension"])} · {html.escape(item["severity"])} · {item["failed"]} open across {item["deployments"]} deployments</small></div><b class="expand">+</b></summary><div class="catalog-detail"><div><label>What it checks</label><code>{html.escape(item["path"])}</code></div><div><label>Why it matters</label><p>{html.escape(item["why"])}</p></div><div><label>How to improve</label><p>{html.escape(item["recommendation"])}</p></div><div><label>Baseline</label><p>{html.escape(item["standard"])}</p></div></div></details>'
        for item in catalog
    )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CNRA MVP</title>
<style>
:root{--ink:#102e2b;--muted:#71877e;--line:#d7ddd2;--paper:#f4f4ee;--orange:#f06638;--lime:#c8e974}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{max-width:1050px;margin:0 auto;padding:42px 24px 60px}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:25px}.brand{font-weight:800;font-size:20px;letter-spacing:-.07em}.brand i{display:inline-block;width:8px;height:8px;margin-right:4px;border-radius:2px;background:var(--orange)}button{border:0;border-radius:4px;padding:11px 15px;background:var(--ink);color:white;cursor:pointer;font-weight:700;font-size:12px}button:hover{background:var(--orange)}.eyebrow{margin-top:70px;color:var(--orange);font:10px monospace;letter-spacing:.12em;text-transform:uppercase}.hero h1{max-width:680px;margin:17px 0 14px;font-size:clamp(40px,7vw,70px);letter-spacing:-.08em;line-height:.94}.hero p{max-width:560px;color:var(--muted);line-height:1.7}.meta{margin:42px 0 18px;color:var(--muted);font:10px monospace;text-transform:uppercase}.summary{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:28px}.score,.metrics,.findings,.catalog{border:1px solid var(--line);background:#fffef9}.score{padding:28px}.score small,.section-title small,.metric span,.catalog-title small{color:var(--muted);font:10px monospace;letter-spacing:.08em;text-transform:uppercase}.score strong{display:block;margin:25px 0 7px;font-size:86px;letter-spacing:-.1em;line-height:.8}.score em{color:var(--muted);font:14px monospace;font-style:normal;letter-spacing:0}.score span{color:var(--muted);font-size:11px}.metrics{padding:22px 24px}.metric{margin:0 0 24px}.metric:last-of-type{margin-bottom:18px}.metric strong{float:right;font:12px monospace}.metric i{display:block;height:6px;margin-top:10px;background:#e8eee4;border-radius:8px}.metric b{display:block;height:100%;background:var(--orange);border-radius:8px}.metric:nth-child(3n) b{background:var(--lime)}.severity-counts{display:flex;gap:15px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font:10px monospace;text-transform:uppercase}.dot{width:7px;height:7px;display:inline-block;margin-right:5px;border-radius:50%;background:var(--orange)}.dot.medium{background:#d5af3c}.dot.low{background:#91a8a0}.findings,.catalog{margin-top:14px;padding:22px 24px}.section-title,.catalog-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;font-weight:800}.hint{margin-left:12px;color:var(--orange)!important;text-transform:none!important;letter-spacing:0!important}.findings ul{padding:0;margin:0;list-style:none}.findings li{padding:0;border-top:1px solid var(--line)}.finding summary,.catalog-row summary{display:flex;align-items:center;gap:12px;padding:15px 0;cursor:pointer;list-style:none}.finding summary::-webkit-details-marker,.catalog-row summary::-webkit-details-marker{display:none}.finding summary>div,.catalog-row summary>div{display:flex;flex:1;flex-direction:column;gap:4px}.finding summary strong,.catalog-row summary strong{font-size:13px}.finding summary small,.catalog-row summary small{color:var(--muted);font:10px monospace}.expand{color:var(--orange);font-size:20px;font-weight:400}.finding[open] .expand,.catalog-row[open] .expand{transform:rotate(45deg)}.severity{width:56px;padding:5px 4px;text-align:center;font:9px monospace;border-radius:2px;background:#f9d3c5;color:#a33e21}.severity.medium{background:#f4e6af;color:#816d19}.severity.low{background:#e5ece5;color:#58746a}.finding-detail,.catalog-detail{display:grid;grid-template-columns:1fr 1fr;gap:17px;padding:6px 0 22px 68px}.finding-detail label,.catalog-detail label{display:block;margin-bottom:7px;color:var(--orange);font:9px monospace;letter-spacing:.08em;text-transform:uppercase}.finding-detail p,.catalog-detail p{margin:0;color:var(--muted);font-size:12px;line-height:1.6}.finding-detail code,.catalog-detail code{display:block;padding:8px;background:#edf0e9;color:var(--ink);font:10px monospace;overflow:auto}.more-note{margin:17px 0 0;color:var(--muted);font:10px monospace}.all-good{display:flex;align-items:center;gap:12px;padding-top:14px!important}.all-good>span{width:24px;height:24px;display:grid;place-items:center;background:var(--lime);border-radius:50%}.all-good div{display:flex;flex-direction:column;gap:4px}.all-good small{color:var(--muted);font:10px monospace}.catalog-title{margin-bottom:4px}.catalog-intro{margin:0 0 16px;color:var(--muted);font-size:12px;line-height:1.6}.catalog-row{border-top:1px solid var(--line)}.catalog-status{width:78px;padding:5px 4px;text-align:center;font:9px monospace;border-radius:2px;background:#e5ece5;color:#58746a}.catalog-status.open{background:#f9d3c5;color:#a33e21}.catalog-status.not_evaluated{background:#edf0e9;color:#71877e}.catalog-detail{padding-left:90px}.error,.empty{display:flex;flex-direction:column;gap:10px;margin-top:28px;padding:22px;background:#fffef9;border:1px solid var(--line)}.error strong{color:var(--orange)}.error span,.empty span{color:var(--muted)}.error small{font:10px monospace;color:var(--muted)}footer{margin-top:20px;color:var(--muted);font:10px monospace}@media(max-width:650px){.summary{grid-template-columns:1fr}.hero h1{font-size:49px}.shell{padding-top:24px}.eyebrow{margin-top:45px}.finding-detail,.catalog-detail{grid-template-columns:1fr;padding-left:0}.severity{width:54px}.finding summary strong,.catalog-row summary strong{font-size:12px}}
</style></head><body><main class="shell"><header class="top"><div class="brand"><i></i>CNRA <span style="color:#71877e;font-size:10px;letter-spacing:0">/ MVP</span></div><button onclick="location.reload()">Run scan ↗</button></header><div class="eyebrow">Cloud native readiness analyzer</div><section class="hero"><div><h1>How ready is your cluster?</h1><p>A read-only scan of your Kubernetes Deployments against a catalog of 27 practical cloud-native rules.</p></div></section><div class="meta">MODE: __MODE__ · NAMESPACE: __NAMESPACE__ · GENERATED: __TIME__</div>__CONTENT__<section class="catalog"><div class="catalog-title"><span>Rule catalog</span><small>__RULE_COUNT__ rules tracked</small></div><p class="catalog-intro">Every rule is transparent: inspect the field we check, why it matters, and the recommended improvement. This catalog includes passing and open checks.</p>__CATALOG__</section><footer>CNRA MVP · Read-only access · <a href="/healthz" style="color:#f06638">healthz</a> · <a href="/api/catalog" style="color:#f06638">catalog API</a></footer></main></body></html>""".replace("__MODE__", html.escape(report.get("mode", "unknown"))).replace("__NAMESPACE__", html.escape(str(report.get("namespace", "—")))).replace("__TIME__", html.escape(report.get("generatedAt", "—"))).replace("__CONTENT__", content).replace("__CATALOG__", catalog_markup).replace("__RULE_COUNT__", str(len(catalog)))


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
        elif self.path == "/api/catalog":
            self.send_body(json.dumps(_catalog()), "application/json")
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
