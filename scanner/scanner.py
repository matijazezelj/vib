"""
VIB Scanner — Vulnerability in a Box

Discovers running container images via Docker socket, scans them with Trivy,
pushes CVE metrics to VictoriaMetrics, and optionally feeds findings into AIB.
"""

import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import docker
import requests
import schedule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("vib")

_shutdown = False


def _handle_sigterm(signum, frame):
    global _shutdown
    _shutdown = True


signal.signal(signal.SIGTERM, _handle_sigterm)

# ── Config ──────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://vib-victoriametrics:8428")
SCAN_INTERVAL_HOURS = float(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
SCAN_ON_STARTUP = os.environ.get("SCAN_ON_STARTUP", "true").lower() == "true"
SEVERITY_FILTER = os.environ.get("SEVERITY_FILTER", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT", "300"))
IGNORE_UNFIXED = os.environ.get("IGNORE_UNFIXED", "false").lower() == "true"

AIB_BASE_URL = os.environ.get("AIB_BASE_URL", "").rstrip("/")
AIB_API_TOKEN = os.environ.get("AIB_API_TOKEN", "")

# Single remote host (backwards-compat). Prefer DOCKER_HOSTS for multi-host.
DOCKER_HOST = os.environ.get("DOCKER_HOST", "")

ADDITIONAL_IMAGES = [
    img.strip()
    for img in os.environ.get("ADDITIONAL_IMAGES", "").split(",")
    if img.strip()
]


# ── Multi-host parsing ────────────────────────────────────────────────────────

def _parse_docker_hosts() -> list[tuple[str, str]]:
    """Return list of (name, docker_url) to scan.

    Priority:
      1. DOCKER_HOSTS=name1=tcp://host1:port1,name2=tcp://host2:port2
      2. DOCKER_HOST=tcp://host:port  (single host, name="docker")
      3. local socket                 (name="local", url="")
    """
    raw = os.environ.get("DOCKER_HOSTS", "").strip()
    if raw:
        hosts = []
        valid_schemes = ("tcp://", "unix://", "ssh://", "npipe://")
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "=" in entry:
                name, url = entry.split("=", 1)
                name, url = name.strip(), url.strip()
            else:
                name, url = "docker", entry.strip()
            if not name or not url:
                logger.warning("Skipping DOCKER_HOSTS entry with empty name or url: %r", entry)
                continue
            if not url.startswith(valid_schemes):
                logger.warning("Skipping DOCKER_HOSTS entry with invalid scheme: %r", entry)
                continue
            hosts.append((name, url))
        return hosts
    if DOCKER_HOST:
        return [("docker", DOCKER_HOST)]
    return [("local", "")]


# ── Docker client helper ──────────────────────────────────────────────────────

def _docker_client(docker_url: str) -> docker.DockerClient:
    return docker.DockerClient(base_url=docker_url) if docker_url else docker.from_env()


# ── Trivy scanning ───────────────────────────────────────────────────────────

def scan_image(image: str, docker_url: str = "") -> Optional[dict]:
    """Run trivy against an image, return parsed JSON or None on failure."""
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--timeout", f"{TRIVY_TIMEOUT}s",
        "--severity", SEVERITY_FILTER,
        "--quiet",
    ]
    if docker_url:
        cmd.extend(["--docker-host", docker_url])
    if IGNORE_UNFIXED:
        cmd.append("--ignore-unfixed")
    cmd.append(image)

    logger.info("Scanning %s", image)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TRIVY_TIMEOUT + 30,
        )
        if result.returncode not in (0, 1):  # trivy exits 1 when vulns found
            logger.warning("Trivy exited %d for %s: %s", result.returncode, image, result.stderr[:300])
            return None
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        logger.error("Trivy timed out scanning %s", image)
        return None
    except json.JSONDecodeError as e:
        logger.error("Failed to parse trivy output for %s: %s", image, e)
        return None
    except Exception as e:
        logger.error("Error scanning %s: %s", image, e)
        return None


def extract_vulnerabilities(scan_result: dict) -> list[dict]:
    """Flatten trivy JSON results into a list of vulnerability dicts."""
    vulns = []
    artifact = scan_result.get("ArtifactName", "unknown")
    for result in scan_result.get("Results", []):
        target = result.get("Target", artifact)
        pkg_type = result.get("Type", "unknown")
        for v in result.get("Vulnerabilities") or []:
            vulns.append({
                "image": artifact,
                "target": target,
                "pkg_type": pkg_type,
                "cve_id": v.get("VulnerabilityID", ""),
                "package": v.get("PkgName", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version": v.get("FixedVersion", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "title": v.get("Title", ""),
                "has_fix": bool(v.get("FixedVersion")),
                "cvss_score": _extract_cvss(v),
            })
    return vulns


def _extract_cvss(v: dict) -> float:
    """Extract the highest CVSS score available."""
    cvss = v.get("CVSS") or {}
    scores = []
    for source in cvss.values():
        for key in ("V3Score", "V2Score"):
            if (score := source.get(key)) is not None:
                scores.append(float(score))
    return max(scores) if scores else 0.0


# ── Metrics push ─────────────────────────────────────────────────────────────

def _safe_label(value: str) -> str:
    """Escape characters that break Prometheus label values."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def push_metrics(image: str, vulns: list[dict], scan_ts: float, host: str = "local") -> None:
    """Push scan results to VictoriaMetrics in Prometheus line format."""
    lines = []
    ts_ms = int(scan_ts * 1000)

    # Aggregate counts by severity
    severity_counts: dict[str, int] = {}
    for v in vulns:
        sev = v["severity"]
        has_fix = "true" if v["has_fix"] else "false"
        key = (sev, has_fix)
        severity_counts[key] = severity_counts.get(key, 0) + 1

    safe_image = _safe_label(image)
    safe_host = _safe_label(host)

    for (sev, has_fix), count in severity_counts.items():
        lines.append(
            f'vib_vulnerabilities_total{{image="{safe_image}",severity="{sev}",'
            f'has_fix="{has_fix}",host="{safe_host}"}} {count} {ts_ms}'
        )

    # Per-CVE info metric (value = CVSS score or 1)
    for v in vulns:
        cve = _safe_label(v["cve_id"])
        pkg = _safe_label(v["package"])
        sev = v["severity"]
        has_fix = "true" if v["has_fix"] else "false"
        score = v["cvss_score"] or 1.0
        lines.append(
            f'vib_cve_info{{image="{safe_image}",cve_id="{cve}",package="{pkg}",'
            f'severity="{sev}",has_fix="{has_fix}",host="{safe_host}"}} {score} {ts_ms}'
        )

    lines.append(f'vib_scan_timestamp{{image="{safe_image}",host="{safe_host}"}} {scan_ts} {ts_ms}')
    lines.append(f'vib_image_vulnerabilities_total{{image="{safe_image}",host="{safe_host}"}} {len(vulns)} {ts_ms}')

    payload = "\n".join(lines)
    for attempt in range(2):
        try:
            resp = requests.post(
                f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
                data=payload,
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            resp.raise_for_status()
            logger.info("Pushed %d metric lines for %s", len(lines), image)
            break
        except Exception as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push metrics for %s after retry: %s", image, e)


def push_scan_summary(images_scanned: int, total_vulns: int, scan_ts: float) -> None:
    """Push overall scan summary metrics (aggregated across all hosts)."""
    ts_ms = int(scan_ts * 1000)
    payload = "\n".join([
        f"vib_images_scanned_total {images_scanned} {ts_ms}",
        f"vib_total_vulnerabilities {total_vulns} {ts_ms}",
        f"vib_last_scan_timestamp {scan_ts} {ts_ms}",
    ])
    for attempt in range(2):
        try:
            resp = requests.post(
                f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
                data=payload,
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            resp.raise_for_status()
            break
        except Exception as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push scan summary after retry: %s", e)


# ── Docker image discovery ────────────────────────────────────────────────────

def discover_images(docker_url: str = "") -> list[str]:
    """Return unique image names from all running containers on the given host."""
    try:
        client = _docker_client(docker_url)
        images = set()
        for container in client.containers.list():
            try:
                if container.image and container.image.tags:
                    images.add(container.image.tags[0])
                elif container.image:
                    images.add(container.image.id)
            except Exception:
                continue
        logger.info("Discovered %d running images", len(images))
        return sorted(images)
    except Exception as e:
        logger.warning("Docker discovery failed: %s", e)
        return []


# ── AIB integration ───────────────────────────────────────────────────────────

def report_to_aib(image: str, vulns: list[dict]) -> None:
    """POST critical/high findings to AIB as audit findings for the image asset."""
    if not AIB_BASE_URL:
        return

    critical_high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
    if not critical_high:
        return

    headers = {"Content-Type": "application/json"}
    if AIB_API_TOKEN:
        headers["Authorization"] = f"Bearer {AIB_API_TOKEN}"

    findings_payload = [
        {
            "title": f"[VIB] {v['cve_id']} in {v['package']} ({v['severity']})",
            "severity": v["severity"].lower(),
            "source": "vib",
            "image": image,
            "cve_id": v["cve_id"],
            "fixed_version": v["fixed_version"],
        }
        for v in critical_high[:20]
    ]

    try:
        resp = requests.post(
            f"{AIB_BASE_URL}/api/v1/graph/findings",
            json={"image": image, "findings": findings_payload},
            headers=headers,
            timeout=10,
        )
        if resp.status_code not in (200, 201, 204):
            logger.debug("AIB findings push returned %d", resp.status_code)
        else:
            logger.info("Reported %d findings to AIB for %s", len(findings_payload), image)
    except Exception as e:
        logger.debug("AIB reporting skipped for %s: %s", image, e)


# ── Main scan loop ────────────────────────────────────────────────────────────

def run_scan() -> None:
    logger.info("─── Starting vulnerability scan ───")
    scan_ts = time.time()
    hosts = _parse_docker_hosts()

    total_vulns = 0
    images_scanned = 0

    for host_name, docker_url in hosts:
        logger.info("── Host: %s (%s) ──", host_name, docker_url or "local socket")
        images = discover_images(docker_url)
        images = list(dict.fromkeys(images))

        if not images:
            logger.warning("No images on %s. Check socket/DOCKER_HOSTS or set ADDITIONAL_IMAGES.", host_name)
            continue

        for image in images:
            result = scan_image(image, docker_url)
            if result is None:
                continue

            vulns = extract_vulnerabilities(result)
            total_vulns += len(vulns)
            images_scanned += 1

            push_metrics(image, vulns, scan_ts, host=host_name)
            report_to_aib(image, vulns)

            crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
            high = sum(1 for v in vulns if v["severity"] == "HIGH")
            logger.info("  %s — %d vulns (%d critical, %d high)", image, len(vulns), crit, high)

    # Scan ADDITIONAL_IMAGES once, outside the per-host loop, under "additional" host label
    if ADDITIONAL_IMAGES:
        logger.info("── Host: additional (extra images) ──")
        for image in ADDITIONAL_IMAGES:
            result = scan_image(image, "")
            if result is None:
                continue

            vulns = extract_vulnerabilities(result)
            total_vulns += len(vulns)
            images_scanned += 1

            push_metrics(image, vulns, scan_ts, host="additional")
            report_to_aib(image, vulns)

            crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
            high = sum(1 for v in vulns if v["severity"] == "HIGH")
            logger.info("  %s — %d vulns (%d critical, %d high)", image, len(vulns), crit, high)

    push_scan_summary(images_scanned, total_vulns, scan_ts)
    logger.info("─── Scan complete: %d images across %d host(s), %d vulnerabilities ───",
                images_scanned, len(hosts), total_vulns)


def main() -> None:
    if "--once" in sys.argv:
        run_scan()
        return

    logger.info("VIB scanner starting (interval=%.1fh)", SCAN_INTERVAL_HOURS)

    if SCAN_ON_STARTUP:
        run_scan()

    schedule.every(SCAN_INTERVAL_HOURS).hours.do(run_scan)

    while True:
        if _shutdown:
            logger.info("SIGTERM received, exiting.")
            break
        schedule.run_pending()
        time.sleep(30)


if __name__ == "__main__":
    main()
