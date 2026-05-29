# Contributing

PRs and issues welcome. A few ground rules:

1. **One concern per PR.** Keep diffs focused — scanner changes separate from dashboard changes.
2. **Test locally first.** Run `make up` and verify the scanner produces metrics before opening a PR.
3. **No new runtime dependencies** without a discussion issue first. The goal is a minimal, self-contained stack.
4. **Dashboard changes:** export the updated JSON from Grafana and replace `grafana/dashboards/vib-overview.json`. Don't hand-edit the JSON.

## Dev setup

```bash
cp .env.example .env
make up
# scanner logs
docker logs -f vib-scanner
```
