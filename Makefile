.PHONY: up down restart logs build clean scan-now

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

build:
	docker compose build --no-cache

logs:
	docker compose logs -f

scan-now:
	docker exec vib-scanner python /app/scanner.py --once

clean:
	docker compose down -v
	docker rmi vib-scanner 2>/dev/null || true
