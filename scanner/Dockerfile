FROM python:3.12-alpine

ARG TRIVY_VERSION=0.70.0
ARG TARGETARCH

RUN apk add --no-cache curl ca-certificates docker-cli

# Trivy names its release assets by its own arch labels, not Docker's TARGETARCH.
RUN case "${TARGETARCH:-amd64}" in \
        amd64) trivy_arch=Linux-64bit ;; \
        arm64) trivy_arch=Linux-ARM64 ;; \
        arm)   trivy_arch=Linux-ARM ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${trivy_arch}.tar.gz" \
    | tar -xz -C /usr/local/bin trivy && \
    trivy --version

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .

# Pre-warm Trivy DB
RUN trivy image --download-db-only --quiet || true

CMD ["python", "scanner.py"]
