# Changelog

All notable changes to VIB are documented here.

## [0.1.0] — 2026-05-29

### Added
- Trivy-based scanner with automatic Docker container image discovery
- VictoriaMetrics time-series storage for CVE metrics
- Grafana dashboard with 9 panels: critical/high/medium counts, trend chart, severity pie, per-image table, CVE detail table with NVD links
- AIB integration — feeds critical/high findings into the asset graph
- `ADDITIONAL_IMAGES` support for scanning images not currently running
- `SCAN_ON_STARTUP` option to run a full scan immediately on start
- Configurable severity filter, ignore-unfixed flag, and Trivy timeout
