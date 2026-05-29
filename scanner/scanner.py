"""
VIB Scanner — Vulnerability in a Box

Discovers running container images via Docker socket, scans them with Trivy,
pushes CVE metrics to VictoriaMetrics, and optionally feeds findings into AIB.
"""

import json
import logging
import os
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

# ── Config ──────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://vib-victoriametrics:8428")
SCAN_INTERVAL_HOURS = float(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
SCAN_ON_STARTUP = os.environ.get("SCAN_ON_STARTUP", "true").lower() == "true"
SEVERITY_FILTER = os.environ.get("SEVERITY_FILTER", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
TRIVY_TIMEOUT = os.environ.get("TRIVY_TIMEOUT", "300")
IGNORE_UNFIXED = os.environ.get("IGNORE_UNFIXED", "false").lower() == "true"

AIB_BASE_URL = os.environ.get("AIB_BASE_URL", "").rstrip("/")
AIB_API_TOKEN = os.environ.get("AIB_API_TOKEN", "")

ADDITIONAL_IMAGES = [
    img.strip()
    for img in os.environ.get("ADDITIONAL_IMAGES", "").split(",")
    if img.strip()
]

# ── Trivy scanning ───────────────────────────────────────────────────────────

def scan_image(image: str) -> Optional[dict]:
    """Run trivy against an image, return parsed JSON or None on failure."""
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--timeout", f"{TRIVY_TIMEOUT}s",
        "--severity", SEVERITY_FILTER,
        "--quiet",
    ]
    if IGNORE_UNFIXED:
        cmd.append("--ignore-unfixed")
    cmd.append(image)

    logger.info("Scanning %s", image)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=int(TRIVY_TIMEOUT) + 30,
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
            if score := source.get(key):
                scores.append(float(score))
    return max(scores) if scores else 0.0


# ── Metrics push ─────────────────────────────────────────────────────────────

def push_metrics(image: str, vulns: list[dict], scan_ts: float) -> None:
    """Push scan results to VictoriaMetrics in Prometheus line format."""
    lines = []
    ts_ms = int(scan_ts * 1000)

    # Aggregate counts by severity
    severity_counts: dict[str, dict] = {}
    for v in vulns:
        sev = v["severity"]
        has_fix = "true" if v["has_fix"] else "false"
        key = (sev, has_fix)
        severity_counts[key] = severity_counts.get(key, 0) + 1

    safe_image = _safe_label(image)

    for (sev, has_fix), count in severity_counts.items():
        lines.append(
            f'vib_vulnerabilities_total{{image="{safe_image}",severity="{sev}",has_fix="{has_fix}"}} '
            f"{count} {ts_ms}"
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
            f'severity="{sev}",has_fix="{has_fix}"}} {score} {ts_ms}'
        )

    # Scan timestamp
    lines.append(f'vib_scan_timestamp{{image="{safe_image}"}} {scan_ts} {ts_ms}')
    # Total vuln count for this image
    lines.append(f'vib_image_vulnerabilities_total{{image="{safe_image}"}} {len(vulns)} {ts_ms}')

    payload = "\n".join(lines)
    try:
        resp = requests.post(
            f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
            data=payload,
            headers={"Content-Type": "text/plain"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Pushed %d metric lines for %s", len(lines), image)
    except Exception as e:
        logger.error("Failed to push metrics for %s: %s", image, e)


def push_scan_summary(images_scanned: int, total_vulns: int, scan_ts: float) -> None:
    """Push overall scan summary metrics."""
    ts_ms = int(scan_ts * 1000)
    payload = "\n".join([
        f"vib_images_scanned_total {images_scanned} {ts_ms}",
        f"vib_total_vulnerabilities {total_vulns} {ts_ms}",
        f"vib_last_scan_timestamp {scan_ts} {ts_ms}",
    ])
    try:
        requests.post(
            f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
            data=payload,
            headers={"Content-Type": "text/plain"},
            timeout=10,
        ).raise_for_status()
    except Exception as e:
        logger.error("Failed to push scan summary: %s", e)


def _safe_label(s: str) -> str:
    """Escape characters that break Prometheus label values."""
    return s.replace('"', '\\"').replace("\n", "").replace("\\", "\\\\")


# ── Docker image discovery ────────────────────────────────────────────────────

def discover_images() -> list[str]:
    """Return unique image names from all running containers."""
    try:
        client = docker.from_env()
        images = set()
        for container in client.containers.list():
            image = container.image.tags[0] if container.image.tags else container.image.id
            images.add(image)
        logger.info("Discovered %d running images", len(images))
        return sorted(images)
    except Exception as e:
        logger.warning("Docker discovery failed: %s — check socket mount", e)
        return []


# ── AIB integration ───────────────────────────────────────────────────────────

def report_to_aib(image: str, vulns: list[dict]) -> None:
    """POST critical/high findings to AIB as audit findings for the image asset."""
    if not AIB_BASE_URL:
        return

    critical_high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
    if not critical_high:
        return

    # Derive a likely AIB node ID from the image name
    # e.g. nginx:latest → might be k8s:pod:default/nginx
    # We can't know for sure without AIB lookup, so we use the resolve endpoint
    image_name = image.split(":")[0].split("/")[-1]
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

    images = discover_images() + ADDITIONAL_IMAGES
    images = list(dict.fromkeys(images))  # deduplicate, preserve order

    if not images:
        logger.warning("No images to scan. Mount /var/run/docker.sock or set ADDITIONAL_IMAGES.")
        push_scan_summary(0, 0, scan_ts)
        return

    total_vulns = 0
    images_scanned = 0

    for image in images:
        result = scan_image(image)
        if result is None:
            continue

        vulns = extract_vulnerabilities(result)
        total_vulns += len(vulns)
        images_scanned += 1

        push_metrics(image, vulns, scan_ts)
        report_to_aib(image, vulns)

        crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
        high = sum(1 for v in vulns if v["severity"] == "HIGH")
        logger.info("  %s — %d vulns (%d critical, %d high)", image, len(vulns), crit, high)

    push_scan_summary(images_scanned, total_vulns, scan_ts)
    logger.info("─── Scan complete: %d images, %d vulnerabilities ───", images_scanned, total_vulns)


def main() -> None:
    if "--once" in sys.argv:
        run_scan()
        return

    logger.info("VIB scanner starting (interval=%.1fh)", SCAN_INTERVAL_HOURS)

    if SCAN_ON_STARTUP:
        run_scan()

    schedule.every(SCAN_INTERVAL_HOURS).hours.do(run_scan)

    while True:
        schedule.run_pending()
        time.sleep(30)


if __name__ == "__main__":
    main()
