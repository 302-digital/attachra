# syntax=docker/dockerfile:1

# Multi-stage build producing a minimal, non-root Attachra image.
# See docs/Attachra_ADR.md (ADR-001: single static binary) and
# .claude/agents/atr-devops.md (minimal, non-root, reproducible image).

# Pinned digest resolves to golang:1.26.5-alpine (verified against the
# Docker Hub registry API and by running `go version` inside the
# image), matching go.mod's `go 1.26.5` toolchain requirement exactly
# so the build never needs to download a newer toolchain at build time.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b AS final

WORKDIR /

COPY --from=builder /out/attachra /attachra
COPY --from=builder --chown=65532:65532 /out/data /data

USER nonroot:nonroot

ENTRYPOINT ["/attachra"]
