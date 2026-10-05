# Changelog

All notable changes to VIB are documented here.

## [Unreleased]

### Fixed
- Images removed from a host, and CVEs fixed in an image, kept their last counts inside every `last_over_time(...[8h])` window, so for two hours after each
  scan the totals were the union of two scans (live: 240 critical against a real 154). At the end of each complete scan the scanner now reads back the
  per-image series from VictoriaMetrics and writes 0 for any it did not report this time. Hosts that could not be listed and images whose scan failed keep
  their last values. The tables hide zero rows.
- The trend graph queried the bare series, so its legend disagreed with the stat tiles (CRITICAL 100 against 240). It now uses the same `last_over_time`
  as the tiles, and "Last Scan" holds its value between scans.

## [0.1.0] — 2026-05-29

### Added
- Trivy-based scanner with automatic Docker container image discovery
- VictoriaMetrics time-series storage for CVE metrics
- Grafana dashboard with 9 panels: critical/high/medium counts, trend chart, severity pie, per-image table, CVE detail table with NVD links
- AIB integration — feeds critical/high findings into the asset graph
- `ADDITIONAL_IMAGES` support for scanning images not currently running
- `SCAN_ON_STARTUP` option to run a full scan immediately on start
- Configurable severity filter, ignore-unfixed flag, and Trivy timeout
