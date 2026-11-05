# pgsafe — dev tasks (Linux/macOS/CI/VPS). On Windows use .\make.ps1 <target>.
COMPOSE := docker compose -f deploy/compose.dev.yml
# server/ and web/ are absent in the open-source mirror (github.com/desnarong/pgsafe).
HAS_SERVER := $(wildcard server/go.mod)
HAS_WEB    := $(wildcard web/package.json)
SERVER_PKGS := $(if $(HAS_SERVER),./server/...,)
PKGS    := ./agent/... $(SERVER_PKGS) ./shared/apitypes/...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo none)

# Release tooling runs from pinned images (keep GORELEASER_IMAGE in sync with release.yml).
GORELEASER_IMAGE := goreleaser/goreleaser:v2.19.0
SHELLCHECK_IMAGE := koalaman/shellcheck:v0.10.0
SH_SCRIPTS       := deploy/install/install.sh deploy/install/install_test.sh deploy/nfpm/postinstall.sh deploy/minio/init.sh
# In a git worktree .git is a pointer file: mount the common git dir so goreleaser can read it.
GIT_ABS_DIR := $(shell git rev-parse --absolute-git-dir 2>/dev/null)
GIT_COMMON  := $(abspath $(shell git rev-parse --git-common-dir 2>/dev/null))
GIT_MOUNT   := $(if $(GIT_ABS_DIR),$(if $(filter $(GIT_ABS_DIR),$(GIT_COMMON)),,-v $(GIT_COMMON):/gitcommon -e GIT_DIR=/gitcommon/worktrees/$(notdir $(GIT_ABS_DIR)) -e GIT_WORK_TREE=/src))
GORELEASER  := docker run --rm -v "$(CURDIR):/src" -w /src $(GIT_MOUNT) \
	-v /var/run/docker.sock:/var/run/docker.sock -v pgsafe-gomod:/go/pkg/mod \
	-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
	$(GORELEASER_IMAGE)

.PHONY: help dev-up dev-down dev-reset dev-logs build test e2e e2e-perf fmt release-check install-test shellcheck

help:
	@echo "targets: dev-up dev-down dev-reset dev-logs build test e2e e2e-perf fmt release-check install-test shellcheck $(PRIVATE_TARGETS)"

dev-up:
	$(COMPOSE) up -d --wait

dev-down:
	$(COMPOSE) down

dev-reset:
	$(COMPOSE) down -v
	$(COMPOSE) up -d --wait

dev-logs:
	$(COMPOSE) logs -f --tail=100

build:
	go build $(PKGS) ./e2e/...
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pgsafe ./agent/cmd/pgsafe
	$(if $(HAS_SERVER),CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/pgsafe-server ./server/cmd/server,)
	$(if $(HAS_WEB),@if command -v npm >/dev/null 2>&1; then $(MAKE) web-build; else echo "npm not found: skipping web build"; fi,)

test:
	go vet $(PKGS)
	go test $(PKGS)

e2e:
	go test -tags e2e -count=1 -timeout 30m -v ./agent/... $(SERVER_PKGS) ./e2e/...

e2e-perf:
	PGSAFE_E2E_PERF=1 go test -tags e2e -count=1 -timeout 60m -v -run TestMaskPerformance ./e2e/...

fmt:
	gofmt -s -w agent $(if $(HAS_SERVER),server,) shared e2e

# Release pipeline dry run: validates .goreleaser.yaml and builds a local snapshot in dist/
# (archives for linux/darwin × amd64/arm64, deb/rpm, checksums, images). Publishes nothing.
release-check:
	$(GORELEASER) check
	$(GORELEASER) release --snapshot --clean --skip=publish,sign,sbom

# install.sh against dist/ (file://) on Alpine and Debian, incl. tampered checksum/archive cases.
install-test:
	@test -f dist/metadata.json || { echo "run make release-check first"; exit 1; }
	docker run --rm -v "$(CURDIR):/src:ro" -v "$(CURDIR)/dist:/dist:ro" alpine:3.20 sh /src/deploy/install/install_test.sh
	docker run --rm -v "$(CURDIR):/src:ro" -v "$(CURDIR)/dist:/dist:ro" debian:bookworm-slim sh /src/deploy/install/install_test.sh

shellcheck:
	docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(SHELLCHECK_IMAGE) --shell=sh $(SH_SCRIPTS)

# Control plane + dashboard targets (not in the open-source mirror).
-include private.mk
