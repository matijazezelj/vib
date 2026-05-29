# Installation

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2 (`docker compose` — not `docker-compose`)
- Outbound internet access on first run (Trivy downloads its vulnerability database, ~200 MB)

## Steps

### 1. Clone and configure

```bash
git clone https://github.com/matijazezelj/vib.git
cd vib
cp .env.example .env
```

Edit `.env` — at minimum set `GRAFANA_ADMIN_PASSWORD`. Leave everything else as defaults to get started.

### 2. Start the stack

```bash
make up
# or: docker compose up -d
```

### 3. Wait for the first scan

The scanner starts immediately. Follow progress with:

```bash
make logs
# or: docker logs -f vib-scanner
```

You'll see lines like:
```
2026-05-29 10:00:01 INFO Starting scan cycle
2026-05-29 10:00:05 INFO Discovered 12 running images
2026-05-29 10:00:05 INFO Scanning nginx:latest...
2026-05-29 10:02:14 INFO   nginx:latest — 47 vulns (3 critical, 12 high)
```

The Trivy vulnerability DB download happens only on first run (cached in a named volume).

### 4. Open Grafana

Navigate to **http://localhost:3001** (or your configured `GRAFANA_PORT`).

Login: `admin` / `GRAFANA_ADMIN_PASSWORD`

The VIB Overview dashboard opens automatically.

---

## Updating

```bash
git pull
docker compose pull          # pull new Grafana/VictoriaMetrics images
make build                   # rebuild scanner
make up                      # apply changes
```

## Uninstalling

```bash
make clean   # removes containers and volumes (all metric history deleted)
```

Or to keep history:
```bash
make down    # stops containers, preserves volumes
```
