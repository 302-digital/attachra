MODULE      := github.com/302-digital/attachra
BINARY      := bin/attachra
CMD_DIR     := ./cmd/attachra
BINARY_CTL  := bin/attachractl
CMD_DIR_CTL := ./cmd/attachractl

# VERSION resolution (ATR-302). Tags are only ever pushed on `staging`
# merge commits (see docs/release-checklist.md), so `dev` and feature
# branches normally have no reachable tag and `git describe --tags`
# fails there.
#
# - If a tag IS reachable from HEAD (staging, or a checkout of a tag
#   itself), use `git describe --tags --dirty` as-is: on the tagged
#   commit this is a clean "vX.Y.Z"; ahead of it, the usual
#   "vX.Y.Z-<n>-g<sha>[-dirty]" describe suffix.
# - Otherwise (dev, feature branches, shallow clones with no tags
#   fetched), fall back to the repo's latest semver tag WITHOUT
#   requiring reachability, and build "<tag>+git.<shortsha>[.dirty]".
#   If the repo has no "v*" tag at all, the fallback tag is "v0.0.0".
#
# Either way the result stays monotonically comparable by dpkg:
# "0.1.0+git.abc1234" sorts above "0.1.0" and below "0.1.1" (see
# DEB_VERSION below). This replaces the previous `--always` fallback,
# which degraded to a bare short SHA on dev and broke deb upgrade
# ordering (a hex SHA like "5ef0f41" compares as a huge fake "version"
# relative to "0.1.1").
VERSION    ?= $(shell \
	if git describe --tags --dirty >/dev/null 2>&1; then \
		git describe --tags --dirty; \
	else \
		tag=$$(git tag --list 'v*' --sort=-v:refname 2>/dev/null | head -1); \
		if [ -z "$$tag" ]; then tag=v0.0.0; fi; \
		sha=$$(git rev-parse --short HEAD 2>/dev/null || echo none); \
		if git diff --quiet 2>/dev/null && git diff --cached --quiet 2>/dev/null; then \
			dirty=; \
		else \
			dirty=.dirty; \
		fi; \
		echo "$$tag+git.$$sha$$dirty"; \
	fi)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE       ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X '$(MODULE)/internal/version.Version=$(VERSION)' \
           -X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
           -X '$(MODULE)/internal/version.Date=$(DATE)'

GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null)

.PHONY: build
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_DIR)

# build-attachractl builds the attachractl CLI (US-9.1/E9, ATR-131): a
# separate static binary from attachra itself (ADR-001's "single static
# binary" is a per-binary property of Go/CGO_ENABLED=0, not a
# one-binary-total constraint) — attachractl is a pure REST API client
# and has no dependency on internal/core's storage/milter/policy
# machinery, so it does not belong in the same binary.
.PHONY: build-attachractl
build-attachractl:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY_CTL) $(CMD_DIR_CTL)

.PHONY: build-all
build-all: build build-attachractl

.PHONY: test
test:
	go test -race ./...

.PHONY: lint
lint:
ifndef GOLANGCI_LINT
	@echo "golangci-lint not found in PATH."
	@echo "Install it with:"
	@echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"
	@echo "or see https://golangci-lint.run/welcome/install/"
	@echo "Skipping lint (not treated as failure)."
else
	golangci-lint run
endif

.PHONY: check
check: test lint

# openapi-lint validates api/openapi.yaml (ATR-195) with Redocly CLI via
# npx, pinned to an exact version so local runs and CI agree. Deliberately
# not a dependency of `check`: `check` must stay usable on a Go-only
# toolchain with no Node/npm installed (CLAUDE.md's "make check green"
# Definition of Done applies to every task, most of which touch no YAML).
# CI validates this spec in its own job instead (see .gitlab-ci.yml).
.PHONY: openapi-lint
openapi-lint:
	npx -y @redocly/cli@1.25.11 lint api/openapi.yaml --config api/redocly.yaml

.PHONY: run
run:
	go run $(CMD_DIR)

.PHONY: e2e
e2e:
	go test -tags e2e -count=1 ./test/e2e/...

# NFPM_VERSION pins the exact nfpm (https://nfpm.goreleaser.com, MIT)
# release used to build the .deb, so local runs and CI always produce
# byte-identical package metadata. nfpm is invoked via `go run
# <module>@<version>` and is deliberately NOT added to go.mod/go.sum
# (build-time-only tool, per deploy/deb/nfpm.yaml's own header comment)
# — this also means build-deb works unmodified on the macOS dev
# machine, since nfpm itself is pure Go and only the packaged binaries
# need to be cross-compiled for linux/amd64.
NFPM_VERSION := v2.47.0
NFPM         := go run github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

DEB_BIN_DIR  := dist/deb-bin
# Debian upstream versions must start with a digit and may not contain
# a bare "-" unless it separates a debian-revision suffix (which we
# don't have here): strip VERSION's leading "v" and fold any remaining
# "-" into "+", which is valid anywhere in an upstream version. This
# covers both VERSION shapes produced above: the on-tag/describe form
# "v0.1.0-5-gabc1234[-dirty]" (dashes from describe's own suffix) and
# the no-reachable-tag fallback "v0.1.0+git.abc1234[.dirty]" (already
# "+"-separated, so the sed here is a no-op on it — "-/+/g" only
# touches "-", it never doubles an existing "+").
DEB_VERSION  := $(shell echo $(VERSION) | sed -e 's/^v//' -e 's/-/+/g')

# print-deb-version exposes DEB_VERSION to the CI publish step (ATR-301) so
# the generic-package-registry URL and SHA256SUMS live at the exact same
# version string `build-deb-%` used for dist/attachra_<version>_<arch>.deb —
# without this, .gitlab-ci.yml would have to re-derive DEB_VERSION with its
# own copy of the sed logic above, which is exactly the kind of drift ATR-302
# was written to eliminate.
.PHONY: print-deb-version
print-deb-version:
	@echo $(DEB_VERSION)

# DEB_ARCHES is every Debian architecture build-deb produces a package
# for (ATR-322): plain "amd64"/"arm64" happen to be valid values for
# both GOARCH and a Debian arch field, so no translation table is
# needed between the two — see build-deb-% below.
DEB_ARCHES   := amd64 arm64

# Man pages (ATR-322): troff sources live in deploy/deb/man/ (hand-
# written — neither cmd/attachra's stdlib flag parsing nor
# cmd/attachractl's cobra tree is wired to a doc generator here), gzipped
# -9n (max compression, no embedded timestamp/name for reproducible
# builds) into dist/deb-man/ before nfpm runs, per FHS/Debian policy for
# /usr/share/man/man<N>/*.gz. See deploy/deb/nfpm.yaml's contents list
# for where each staged file lands.
DEB_MAN_SRC_DIR := deploy/deb/man
DEB_MAN_DIR      := dist/deb-man
DEB_MAN_PAGES    := attachra.1 attachractl.1 attachra.yaml.5
DEB_MAN_GZ       := $(addprefix $(DEB_MAN_DIR)/,$(addsuffix .gz,$(DEB_MAN_PAGES)))

$(DEB_MAN_DIR)/%.gz: $(DEB_MAN_SRC_DIR)/%
	mkdir -p $(DEB_MAN_DIR)
	gzip -9n -c $< > $@

# Without .SECONDARY, GNU Make treats each $(DEB_MAN_GZ) file as a
# throwaway "intermediate" (built only via an implicit pattern rule,
# consumed by build-deb-%'s recipe, never named directly on the command
# line) and silently deletes it after the top-level `build-deb` target
# finishes — even though nfpm already consumed it by then, that deletion
# is still surprising when inspecting dist/deb-man/ afterwards or
# re-running a single build-deb-% target. Keep the staged .gz files
# around instead.
.SECONDARY: $(DEB_MAN_GZ)

# build-deb produces dist/attachra_<version>_<arch>.deb for every arch
# in DEB_ARCHES: Debian packages for grommunio/Debian 13 hosts
# (deploy/deb/) containing static linux/<arch> binaries (ADR-001), man
# pages, shell completions, the systemd unit, config templates and
# integration examples. See docs/deploy/grommunio-debian.md for the
# install/upgrade flow this package targets.
.PHONY: build-deb
build-deb: $(addprefix build-deb-,$(DEB_ARCHES))

# build-deb-% builds and packages a single architecture (% is "amd64" or
# "arm64", matching both a DEB_ARCHES entry and a valid GOARCH value).
# Cross-compilation for arm64 works unmodified from the existing amd64
# build: CGO_ENABLED=0 keeps both binaries pure Go (ADR-001), so no
# arm64 C toolchain is required even when building on an amd64 (or, as
# here, host-arm64 macOS) machine.
.PHONY: build-deb-%
build-deb-%: $(DEB_MAN_GZ)
	mkdir -p $(DEB_BIN_DIR)/$*
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -ldflags "$(LDFLAGS)" -o $(DEB_BIN_DIR)/$*/attachra $(CMD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -ldflags "$(LDFLAGS)" -o $(DEB_BIN_DIR)/$*/attachractl $(CMD_DIR_CTL)
	mkdir -p dist
	DEB_VERSION="$(DEB_VERSION)" DEB_ARCH="$*" DEB_BIN_DIR="$(DEB_BIN_DIR)/$*" $(NFPM) package \
		--config deploy/deb/nfpm.yaml \
		--packager deb \
		--target dist/attachra_$(DEB_VERSION)_$*.deb
