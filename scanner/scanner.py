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
import threading
import time
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

_shutdown = threading.Event()


def _handle_sigterm(signum, frame):
    _shutdown.set()


signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT, _handle_sigterm)

# ── Config ──────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://vib-victoriametrics:8428")
try:
    SCAN_INTERVAL_HOURS = float(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
except ValueError:
    logger.error("FATAL: SCAN_INTERVAL_HOURS must be a number, got %r", os.environ.get("SCAN_INTERVAL_HOURS"))
    sys.exit(1)
if SCAN_INTERVAL_HOURS <= 0:
    logger.error("FATAL: SCAN_INTERVAL_HOURS must be greater than 0, got %r", SCAN_INTERVAL_HOURS)
    sys.exit(1)
SCAN_ON_STARTUP = os.environ.get("SCAN_ON_STARTUP", "true").lower() == "true"
SEVERITY_FILTER = os.environ.get("SEVERITY_FILTER", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
SEVERITIES = [s.strip().upper() for s in SEVERITY_FILTER.split(",") if s.strip()]
try:
    TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT", "300"))
except ValueError:
    logger.error("FATAL: TRIVY_TIMEOUT must be an integer, got %r", os.environ.get("TRIVY_TIMEOUT"))
    sys.exit(1)
if TRIVY_TIMEOUT <= 0:
    logger.error("FATAL: TRIVY_TIMEOUT must be greater than 0, got %r", TRIVY_TIMEOUT)
    sys.exit(1)
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

# Per-image series that a later scan may stop emitting (image removed, CVE fixed). Their last
# non-zero sample would otherwise keep counting inside every last_over_time() window.
STALE_METRICS = ("vib_vulnerabilities_total", "vib_image_vulnerabilities_total", "vib_cve_info")
STALE_LOOKBACK = "48h"


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

def _registry_ref(image: str, docker_url: str) -> Optional[str]:
    """The image's registry digest, so a remote scan reads the bytes the host runs."""
    try:
        digests = _docker_client(docker_url).images.get(image).attrs.get("RepoDigests") or []
        return digests[0] if digests else None
    except Exception:
        return None


def scan_image(image: str, docker_url: str = "") -> Optional[dict]:
    """Run trivy against an image, return parsed JSON or None on failure.

    Some daemons export an image with a layer blob missing, which fails every scan of it
    (exit 1, empty output); the same digest pulled from its registry scans fine.
    """
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--timeout", f"{TRIVY_TIMEOUT}s",
        "--severity", SEVERITY_FILTER,
        "--quiet",
    ]
    if IGNORE_UNFIXED:
        cmd.append("--ignore-unfixed")
    host = ["--docker-host", docker_url] if docker_url else []

    logger.info("Scanning %s", image)
    try:
        result = subprocess.run(cmd + host + [image], capture_output=True, text=True, timeout=TRIVY_TIMEOUT + 30)
        if result.returncode != 0 or not result.stdout:
            ref = _registry_ref(image, docker_url)
            if ref:
                logger.warning("Trivy exited %d for %s, retrying from registry as %s: %s",
                               result.returncode, image, ref, result.stderr[:300])
                result = subprocess.run(cmd + ["--image-src", "remote", ref],
                                        capture_output=True, text=True, timeout=TRIVY_TIMEOUT + 30)
        if result.returncode != 0 or not result.stdout:
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


def dedupe_vulnerabilities(vulns: list[dict]) -> list[dict]:
    """Drop repeated (cve_id, package, target) rows.

    The same CVE can appear once per Result target; VictoriaMetrics keeps only one
    sample per identical label set, so duplicates would silently collapse anyway.
    """
    seen = set()
    unique = []
    for v in vulns:
        key = (v["cve_id"], v["package"], v["target"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(v)
    return unique


def _extract_cvss(v: dict) -> float:
    """Extract the highest CVSS score available."""
    cvss = v.get("CVSS") or {}
    scores = []
    for source in cvss.values():
        if not source or not isinstance(source, dict):
            continue
        for key in ("V3Score", "V2Score"):
            if (score := source.get(key)) is not None:
                scores.append(float(score))
    return max(scores) if scores else 0.0


# ── Metrics push ─────────────────────────────────────────────────────────────

def _safe_label(value: str) -> str:
    """Escape characters that break Prometheus label values."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _series_key(name: str, labels: dict) -> tuple:
    return (name, tuple(sorted(labels.items())))


def push_metrics(image: str, vulns: list[dict], scan_ts: float, host: str = "local") -> set:
    """Push scan results to VictoriaMetrics in Prometheus line format.

    Returns the keys of the per-image series written, for zero_stale_series().
    """
    lines = []
    emitted = set()
    ts_ms = int(scan_ts * 1000)

    # Seed every configured severity at 0 so a remediated CVE reports 0 instead of
    # leaving the previous scan's count as the newest sample for that series.
    severity_counts: dict[tuple, int] = {
        (sev, has_fix): 0 for sev in SEVERITIES for has_fix in ("true", "false")
    }
    for v in vulns:
        key = (v["severity"], "true" if v["has_fix"] else "false")
        severity_counts[key] = severity_counts.get(key, 0) + 1

    safe_image = _safe_label(image)
    safe_host = _safe_label(host)

    for (sev, has_fix), count in severity_counts.items():
        emitted.add(_series_key("vib_vulnerabilities_total",
                                {"image": image, "severity": sev, "has_fix": has_fix, "host": host}))
        lines.append(
            f'vib_vulnerabilities_total{{image="{safe_image}",severity="{_safe_label(sev)}",'
            f'has_fix="{has_fix}",host="{safe_host}"}} {count} {ts_ms}'
        )

    # Per-CVE info metric (value = CVSS score or 1)
    for v in vulns:
        cve = _safe_label(v["cve_id"])
        pkg = _safe_label(v["package"])
        sev = _safe_label(v["severity"])
        has_fix = "true" if v["has_fix"] else "false"
        score = v["cvss_score"] or 1.0
        emitted.add(_series_key("vib_cve_info", {
            "image": image, "cve_id": v["cve_id"], "package": v["package"],
            "severity": v["severity"], "has_fix": has_fix, "host": host,
        }))
        lines.append(
            f'vib_cve_info{{image="{safe_image}",cve_id="{cve}",package="{pkg}",'
            f'severity="{sev}",has_fix="{has_fix}",host="{safe_host}"}} {score} {ts_ms}'
        )

    lines.append(f'vib_scan_timestamp{{image="{safe_image}",host="{safe_host}"}} {scan_ts} {ts_ms}')
    lines.append(f'vib_image_vulnerabilities_total{{image="{safe_image}",host="{safe_host}"}} {len(vulns)} {ts_ms}')
    emitted.add(_series_key("vib_image_vulnerabilities_total", {"image": image, "host": host}))

    payload = "\n".join(lines)
    for attempt in range(2):
        try:
            resp = requests.post(
                f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
                data=payload,
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            if 400 <= resp.status_code < 500:
                logger.error(
                    "Failed to push metrics for %s: HTTP %d (not retrying 4xx): %s",
                    image, resp.status_code, resp.text[:300],
                )
                return emitted
            resp.raise_for_status()
            logger.info("Pushed %d metric lines for %s", len(lines), image)
            return emitted
        except requests.exceptions.ConnectionError as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push metrics for %s after retry: %s", image, e)
        except requests.exceptions.HTTPError as e:
            # 5xx — retryable
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push metrics for %s after retry: %s", image, e)
        except requests.exceptions.Timeout as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push metrics for %s after retry: %s", image, e)
        except Exception as e:
            logger.error("Failed to push metrics for %s: %s", image, e)
            return emitted
    return emitted


def push_scan_error(image: str, host: str, scan_ts: float) -> None:
    """Push a vib_scan_errors_total counter when a Trivy scan/parse fails."""
    ts_ms = int(scan_ts * 1000)
    safe_image = _safe_label(image)
    safe_host = _safe_label(host)
    payload = f'vib_scan_errors_total{{image="{safe_image}",host="{safe_host}"}} 1 {ts_ms}'
    try:
        resp = requests.post(
            f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
            data=payload,
            headers={"Content-Type": "text/plain"},
            timeout=10,
        )
        if 400 <= resp.status_code < 500:
            logger.error(
                "Failed to push scan error metric: HTTP %d: %s",
                resp.status_code, resp.text[:300],
            )
            return
        resp.raise_for_status()
    except Exception as e:
        logger.warning("Failed to push scan error metric for %s: %s", image, e)


def zero_stale_series(emitted: set, scanned_hosts: set, failed: set, scan_ts: float) -> None:
    """Write 0 for per-image series an earlier scan wrote and this one did not.

    Previous series are read back from VictoriaMetrics rather than kept in memory, so this
    also works on the first scan after a restart. Series on a host that was not scanned, or
    for an image whose scan failed, keep their last value: no result is not a clean result.
    """
    ts_ms = int(scan_ts * 1000)
    lines = []
    for name in STALE_METRICS:
        try:
            resp = requests.get(
                f"{VICTORIAMETRICS_URL}/api/v1/query",
                params={"query": f"last_over_time({name}[{STALE_LOOKBACK}]) > 0"},
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json()["data"]["result"]
        except Exception as e:
            logger.warning("Skipping stale-series cleanup, could not read %s: %s", name, e)
            return
        for series in result:
            labels = {k: v for k, v in series["metric"].items() if k != "__name__"}
            host, image = labels.get("host"), labels.get("image")
            if host not in scanned_hosts or (image, host) in failed:
                continue
            if _series_key(name, labels) in emitted:
                continue
            label_str = ",".join(f'{k}="{_safe_label(v)}"' for k, v in sorted(labels.items()))
            lines.append(f"{name}{{{label_str}}} 0 {ts_ms}")

    if not lines:
        return
    for attempt in range(2):
        try:
            resp = requests.post(
                f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
                data="\n".join(lines),
                headers={"Content-Type": "text/plain"},
                timeout=30,
            )
            resp.raise_for_status()
            logger.info("Zeroed %d series no longer reported by this scan", len(lines))
            return
        except Exception as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to zero stale series: %s", e)


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
            if 400 <= resp.status_code < 500:
                logger.error(
                    "Failed to push scan summary: HTTP %d (not retrying 4xx): %s",
                    resp.status_code, resp.text[:300],
                )
                return
            resp.raise_for_status()
            return
        except requests.exceptions.ConnectionError as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push scan summary after retry: %s", e)
        except requests.exceptions.HTTPError as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push scan summary after retry: %s", e)
        except requests.exceptions.Timeout as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Failed to push scan summary after retry: %s", e)
        except Exception as e:
            logger.error("Failed to push scan summary: %s", e)
            return


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
            logger.warning("AIB findings push returned %d", resp.status_code)
        else:
            logger.info("Reported %d findings to AIB for %s", len(findings_payload), image)
    except Exception as e:
        logger.warning("AIB reporting failed for %s: %s", image, e)


# ── Main scan loop ────────────────────────────────────────────────────────────

def run_scan() -> None:
    logger.info("─── Starting vulnerability scan ───")
    scan_ts = time.time()
    hosts = _parse_docker_hosts()

    total_vulns = 0
    images_scanned = 0
    emitted: set = set()
    scanned_hosts: set = set()
    failed: set = set()

    for host_name, docker_url in hosts:
        if _shutdown.is_set():
            logger.info("Shutdown requested, aborting scan loop.")
            break
        logger.info("── Host: %s (%s) ──", host_name, docker_url or "local socket")
        images = discover_images(docker_url)

        if not images:
            logger.warning("No images on %s. Check socket/DOCKER_HOSTS or set ADDITIONAL_IMAGES.", host_name)
            continue
        scanned_hosts.add(host_name)

        for image in images:
            if _shutdown.is_set():
                logger.info("Shutdown requested, aborting scan loop.")
                break
            result = scan_image(image, docker_url)
            if result is None:
                push_scan_error(image, host_name, scan_ts)
                failed.add((image, host_name))
                continue

            try:
                vulns = dedupe_vulnerabilities(extract_vulnerabilities(result))
            except Exception as e:
                logger.error("Failed to extract vulnerabilities for %s: %s", image, e)
                push_scan_error(image, host_name, scan_ts)
                failed.add((image, host_name))
                continue

            total_vulns += len(vulns)
            images_scanned += 1

            emitted |= push_metrics(image, vulns, scan_ts, host=host_name)
            report_to_aib(image, vulns)

            crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
            high = sum(1 for v in vulns if v["severity"] == "HIGH")
            logger.info("  %s — %d vulns (%d critical, %d high)", image, len(vulns), crit, high)

    # Scan ADDITIONAL_IMAGES once, outside the per-host loop, under "additional" host label
    if ADDITIONAL_IMAGES and not _shutdown.is_set():
        # Pick a docker_url for ADDITIONAL_IMAGES: prefer local socket, fall back to first remote
        local_available = os.path.exists("/var/run/docker.sock")
        additional_docker_url = ""
        skip_additional = False
        if not local_available:
            remote_hosts = [(n, u) for (n, u) in hosts if u]
            if remote_hosts:
                fallback_name, fallback_url = remote_hosts[0]
                logger.warning(
                    "Local Docker socket unavailable; ADDITIONAL_IMAGES will use remote host %r (%s).",
                    fallback_name, fallback_url,
                )
                additional_docker_url = fallback_url
            else:
                logger.warning(
                    "Local Docker socket unavailable and no remote DOCKER_HOSTS configured; "
                    "skipping ADDITIONAL_IMAGES scanning."
                )
                skip_additional = True

        if not skip_additional:
            logger.info("── Host: additional (extra images) ──")
            scanned_hosts.add("additional")
            for image in ADDITIONAL_IMAGES:
                if _shutdown.is_set():
                    logger.info("Shutdown requested, aborting scan loop.")
                    break
                result = scan_image(image, additional_docker_url)
                if result is None:
                    push_scan_error(image, "additional", scan_ts)
                    failed.add((image, "additional"))
                    continue

                try:
                    vulns = dedupe_vulnerabilities(extract_vulnerabilities(result))
                except Exception as e:
                    logger.error("Failed to extract vulnerabilities for %s: %s", image, e)
                    push_scan_error(image, "additional", scan_ts)
                    failed.add((image, "additional"))
                    continue

                total_vulns += len(vulns)
                images_scanned += 1

                emitted |= push_metrics(image, vulns, scan_ts, host="additional")
                report_to_aib(image, vulns)

                crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
                high = sum(1 for v in vulns if v["severity"] == "HIGH")
                logger.info("  %s — %d vulns (%d critical, %d high)", image, len(vulns), crit, high)

    # An interrupted scan did not see every image, so it cannot tell which ones are gone.
    if not _shutdown.is_set():
        zero_stale_series(emitted, scanned_hosts, failed, scan_ts)

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
        if _shutdown.is_set():
            logger.info("Shutdown signal received, exiting.")
            break
        schedule.run_pending()
        if _shutdown.wait(30):
            logger.info("Shutdown signal received, exiting.")
            break


if __name__ == "__main__":
    main()
