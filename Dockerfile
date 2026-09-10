# =============================================================================
# CyberDefense XDR — Dockerfile
# =============================================================================
# Production-oriented multi-stage build for the Flask XDR application.
# Includes security scanning tools: TShark, Nmap, Nikto, WhatWeb, testssl.sh
# =============================================================================

FROM python:3.13-slim-bookworm AS base

# Metadata
LABEL maintainer="CyberDefense XDR Project"
LABEL description="AI-Powered Extended Detection and Response Platform"
LABEL version="0.1.0"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# System Dependencies
# ---------------------------------------------------------------------------
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections \
    && apt-get update && apt-get install -y --no-install-recommends \
    # PostgreSQL client (for pg_isready in entrypoint)
    postgresql-client \
    # TShark + capinfos (Wireshark CLI tools for packet analysis)
    tshark \
    # Nmap (network/vulnerability scanner)
    nmap \
    # WhatWeb (web technology fingerprinter)
    whatweb \
    # testssl.sh (TLS/SSL assessment)
    testssl.sh \
    # Perl + SSL module (runtime for Nikto)
    perl \
    libnet-ssleay-perl \
    ca-certificates \
    # Build tools for Python packages with C extensions
    gcc \
    libpq-dev \
    # Utility tools
    curl \
    unzip \
    && apt-get purge -y --auto-remove gcc \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Nikto Installation (official release)
# ---------------------------------------------------------------------------
ARG NIKTO_VERSION=2.5.0
RUN curl -sSfL "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz" -o /tmp/nikto.tar.gz \
    && tar -xzf /tmp/nikto.tar.gz -C /opt \
    && ln -s /opt/nikto-${NIKTO_VERSION}/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto-${NIKTO_VERSION}/program/nikto.pl \
    && rm /tmp/nikto.tar.gz

# ---------------------------------------------------------------------------
# Nuclei Installation (official binary release)
# ---------------------------------------------------------------------------
ARG NUCLEI_VERSION=3.3.7
ARG TARGETARCH=amd64
RUN curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
    -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# ---------------------------------------------------------------------------
# Application Setup
# ---------------------------------------------------------------------------
WORKDIR /app

# Install Python dependencies first (Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/
COPY config/ config/
COPY migrations/ migrations/
COPY run.py .
COPY docker/entrypoint.sh /entrypoint.sh

# Create non-root application user
RUN groupadd -r xdr && useradd -r -g xdr -d /app -s /sbin/nologin xdr \
    && mkdir -p instance/pcap_uploads instance/ids instance/reports logs \
    && chown -R xdr:xdr /app instance logs \
    && chmod 750 instance/pcap_uploads

# ---------------------------------------------------------------------------
# Runtime Configuration
# ---------------------------------------------------------------------------
USER xdr

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -sf http://localhost:5000/auth/login || exit 1

ENTRYPOINT ["/entrypoint.sh"]

