FROM python:3.12-alpine

ARG TRIVY_VERSION=0.70.0
ARG TARGETARCH=amd64

RUN apk add --no-cache curl ca-certificates docker-cli

# Install Trivy
RUN curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy && \
    trivy --version

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .

# Pre-warm Trivy DB
RUN trivy image --download-db-only --quiet || true

CMD ["python", "scanner.py"]
