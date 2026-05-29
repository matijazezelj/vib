# Roadmap

## v0.2
- [ ] Slack / Teams alert webhook for new critical CVEs
- [ ] Per-image ignore lists (`.trivyignore` per image)
- [ ] Kubernetes pod scanning via kubeconfig mount
- [ ] SBOM export (CycloneDX / SPDX) alongside metrics

## v0.3
- [ ] Multi-host scanning via remote Docker socket
- [ ] Historical CVE trend comparison (week-over-week delta)
- [ ] OIB integration — expose CVE counts as OpenCost context

## Backlog
- GitHub Container Registry / ECR / GCR image scanning without a running container
- Policy-as-code: fail scan if critical CVE count exceeds threshold
- Auto-open GitHub issues for newly discovered critical CVEs
