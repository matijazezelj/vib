# Integrations

## AIB — Asset Inventory in a Box

VIB can push critical and high-severity findings into [AIB](https://github.com/matijazezelj/aib), linking vulnerabilities to assets in your inventory graph. This lets you answer questions like "which of my production services has a critical unpatched CVE?" directly inside AIB.

### How it works

After each scan, VIB:
1. Filters findings to `CRITICAL` and `HIGH` severity only
2. Derives the image name (e.g. `nginx` from `nginx:latest`)
3. Calls AIB's `GET /api/v1/graph/nodes/resolve?hostname=<image-name>` to find the matching asset node
4. POSTs findings to `POST /api/v1/graph/findings` on that node

### Setup

In your `.env`:

```env
AIB_BASE_URL=http://aib:8080
AIB_API_TOKEN=your-token-here
```

If AIB is on the same Docker network, use the container name. Otherwise use the host/IP.

### Finding format sent to AIB

```json
{
  "node_id": "k8s:pod:default/nginx",
  "source": "vib-trivy",
  "findings": [
    {
      "id": "CVE-2024-1234",
      "severity": "CRITICAL",
      "title": "CVE-2024-1234 in libssl3 (nginx:latest)",
      "description": "...",
      "remediation": "Upgrade to libssl3 3.0.x",
      "metadata": {
        "package": "libssl3",
        "installed_version": "3.0.2-0ubuntu1",
        "fixed_version": "3.0.2-0ubuntu1.10",
        "cvss_score": "9.8",
        "has_fix": "true",
        "image": "nginx:latest"
      }
    }
  ]
}
```

### Graceful degradation

If AIB is unreachable or the hostname can't be resolved to a node, VIB logs a warning and continues — AIB integration never blocks or fails the scan cycle.

---

## SIB — Security Intelligence in a Box

[SIB](https://github.com/matijazezelj/sib) can query AIB for asset context, which means VIB findings surfaced via AIB will automatically enrich SIB's LLM-powered alert triage. No direct VIB↔SIB integration is needed — AIB is the bridge.

---

## Alerting

VIB doesn't ship its own alertmanager, but since metrics are in VictoriaMetrics (Prometheus-compatible), you can wire it to any existing alerting stack:

- **Prometheus Alertmanager**: point a remote_write to VictoriaMetrics, or scrape VictoriaMetrics `/api/v1/export/prometheus`
- **Grafana Alerting**: create alert rules directly on the Grafana panels — Grafana reads from the provisioned VictoriaMetrics datasource

Example Grafana alert for new critical CVEs:
```
ALERT: vib_vulnerabilities_total{severity="CRITICAL"} > 0
```
