# syntax=docker/dockerfile:1

# Multi-stage build producing a minimal, non-root Attachra image.
# See docs/Attachra_ADR.md (ADR-001: single static binary) and
# .claude/agents/atr-devops.md (minimal, non-root, reproducible image).

FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# Serial package compilation and capped GC target: compiling
# modernc.org/sqlite concurrently spikes memory and OOMKills the CI
# runner (exit 137). Mirrors the tuning in .gitlab-ci.yml build-test.
ENV GOFLAGS=-p=1 \
    GOMAXPROCS=2 \
    GOMEMLIMIT=1750MiB \
    GOGC=50

RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w \
    -X github.com/302-digital/attachra/internal/version.Version=${VERSION} \
    -X github.com/302-digital/attachra/internal/version.Commit=${COMMIT} \
    -X github.com/302-digital/attachra/internal/version.Date=${DATE}" \
    -o /out/attachra \
    ./cmd/attachra

# Empty dir template for the /data volume: distroless has no shell to
# mkdir/chown at runtime, so ownership must be baked into the image for
# named volumes to be writable by the nonroot user (uid 65532).
RUN mkdir -p /out/data

# Final stage: distroless static base, no shell, non-root by default.
FROM gcr.io/distroless/static-debian12:nonroot AS final

WORKDIR /

COPY --from=builder /out/attachra /attachra
COPY --from=builder --chown=65532:65532 /out/data /data

USER nonroot:nonroot

ENTRYPOINT ["/attachra"]
