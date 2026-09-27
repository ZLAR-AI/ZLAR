# ZLAR Gate — Linux proof-of-concept
# Proves the bash gate, MCP gate, and Cedar PoC run on Linux.
# Not a production image — no secrets, no Telegram, no runtime config.

FROM node:22-alpine AS base

# bash gate dependencies
RUN apk add --no-cache \
    bash \
    jq \
    curl \
    openssl \
    coreutils

WORKDIR /opt/zlar

# Copy repo contents
COPY . .

# Create runtime directories
RUN mkdir -p var/log var/tmp

# Install Node dependencies — npm ci only, no fallback to npm install.
# Lockfiles are security-critical; if they're out of sync, fail the build.
RUN cd mcp-gate && npm ci --ignore-scripts && cd ..
RUN cd cedar-poc && npm ci --ignore-scripts && cd ..

# Make all bin/ and scripts/ executable
RUN chmod +x bin/* scripts/*

# Smoke test at build time — if this fails, the image doesn't build
RUN bash scripts/smoke-test.sh

ENTRYPOINT ["bash", "bin/zlar-gate"]
