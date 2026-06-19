# quicsql (quicsql.net) — common operations for the network-server nursery.
#
# A separate module (own go.mod, replace gosqlite.org => ..), so these recipes run
# in this module's context. Install just from https://just.systems. Run `just`
# (no args) for the default gate (build + test + lint). Mirrors the root gosqlite
# justfile's shape so the two feel the same.

set dotenv-load := true

# Default recipe: a fast pre-commit gate.
default: build test lint

# List every recipe.
help:
    @just --list

# Build every package + the daemon.
build:
    go build ./...

# Run the full test suite.
test:
    go test -count=1 -timeout 2m ./...

# Verbose test run for diagnosing a flake.
test-v:
    go test -count=1 -timeout 5m -v ./...

# Run a single named test (or regex). Usage: just test-one TestConcurrentColdGet
test-one PATTERN:
    go test -count=1 -timeout 2m -run "{{PATTERN}}" -v ./...

# Race-detector pass (needs cgo — on by default on the host).
test-race:
    go test -race -count=1 -timeout 5m ./...

# Test with coverage; outputs HTML to /tmp/quicsql-cover.html.
coverage:
    go test -count=1 -coverprofile=/tmp/quicsql-cover.out ./...
    go tool cover -html=/tmp/quicsql-cover.out -o /tmp/quicsql-cover.html
    @echo "open /tmp/quicsql-cover.html"

# Run all benchmarks (override duration via `just bench --benchtime=2s`).
bench *FLAGS:
    go test -run=^$ -bench=. -benchmem -count=3 {{FLAGS}} ./...

# Run the daemon. Usage: just run --config quicsql.yaml
run *ARGS:
    go run ./cmd/quicsql {{ARGS}}

# Run the self-contained example: databases across every transport, real-life
# operations, and a per-protocol throughput benchmark. Usage: just demo -dur 5s -workers 64
demo *ARGS:
    go run ./examples/demo {{ARGS}}

# Run the auth/authz matrix demo: every authentication method and authorization
# level, with success and denial paths (exits non-zero if any expectation fails).
auth-demo:
    go run ./examples/auth

# Same matrix, but the credential methods (bearer/password/keyring) ride over a
# server-authenticated TLS h2 listener instead of cleartext — the deployed shape.
auth-demo-tls:
    go run ./examples/auth -tls

# Run the fully-charged deployable server: vault encryption+compression, the
# extension bundle + a custom SQL function, every transport (h2/TLS + h3/QUIC +
# dev extras), every auth method, control plane, limits, and a vault meta store.
# Usage: just charged -hosts your.host,203.0.113.10   (binds 0.0.0.0; Ctrl-C to stop)
charged *ARGS:
    go run ./examples/charged-server {{ARGS}}

# Two-module showcase, run locally as a smoke test: start the fully-charged server
# (encryption+compression, all auth/transports, extensions, a custom function),
# run the remote tour against it over TLS+mTLS, then stop the server. In a real
# deployment the server runs on another host — see examples/quicsql-charged-server.
showcase:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d)
    trap 'kill "${srv:-0}" 2>/dev/null || true; rm -rf "$dir"' EXIT
    (cd ../../sqlite/examples/quicsql-charged-server && go build -o "$dir/charged" .)
    "$dir/charged" -data "$dir/data" -hosts localhost,127.0.0.1 >"$dir/server.log" 2>&1 &
    srv=$!
    for _ in $(seq 1 40); do curl -sf http://127.0.0.1:7775/_health >/dev/null 2>&1 && break; sleep 0.25; done
    (cd ../../sqlite/examples/quicsql-remote-tour && go run . -addr localhost:7777)

# LiteORM Studio (browser DB admin GUI) driving a REMOTE quicSQL database: starts
# an in-process quicSQL server, seeds it, and serves the studio at
# http://localhost:8088/studio/ (dev basic-auth admin/studio). Everything the
# studio does travels over the wire to quicSQL. `just studio -smoke` self-tests
# the API round trip and exits instead of serving.
studio *ARGS:
    cd ../../sqlite/examples/quicsql-studio && go run . {{ARGS}}

# Lint: fmt-check + vet + staticcheck + golangci-lint + modernize (matches CI).
# fmt-check runs first — cheapest, and the most common local-only-push CI failure.
lint: fmt-check vet staticcheck golangci modernize

# go vet across all packages.
vet:
    go vet ./...

# staticcheck. Prefers an installed binary (PATH or GOPATH/bin), falling back to
# `go run` so the recipe never depends on what's on PATH. Install for speed:
# `go install honnef.co/go/tools/cmd/staticcheck@latest`.
staticcheck:
    @bin=$(command -v staticcheck || echo "$(go env GOPATH)/bin/staticcheck"); \
    if [ -x "$bin" ]; then "$bin" ./...; \
    else go run honnef.co/go/tools/cmd/staticcheck@latest ./...; fi

# golangci-lint (v2), pinned to the repo-root config so lint stays consistent
# with the rest of gosqlite. Same PATH-independent shape as staticcheck.
golangci:
    @bin=$(command -v golangci-lint || echo "$(go env GOPATH)/bin/golangci-lint"); \
    if [ -x "$bin" ]; then "$bin" run --timeout 5m --config .golangci.yml; \
    else go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --timeout 5m --config .golangci.yml; fi

# gopls modernize: catches Go-version-bump idioms. Run via `go run` so
# contributors need no separate install. `^go: ` strips Go's auto-toolchain
# breadcrumbs (`go: downloading ...`) so they don't trip the non-empty gate.
modernize:
    @out=$(go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest ./... 2>&1 \
        | grep -v '^exit status' \
        | grep -v '^go: ' \
        || true); \
    if [ -n "$out" ]; then echo "$out"; exit 1; fi

# gofmt diff (read-only). Fails if any file would be reformatted.
fmt-check:
    @out=$(gofmt -d $(find . -name '*.go')); \
    if [ -n "$out" ]; then echo "$out"; exit 1; fi

# Apply gofmt in place.
fmt:
    @gofmt -w $(find . -name '*.go')

# go mod tidy.
tidy:
    go mod tidy

# Cross-compile every package (compile-only) across the target matrix. gosqlite
# is CGo-free, so this is a pure cross-compile with no C toolchain.
cross-build:
    @set -e; \
    for triple in \
        darwin/amd64 darwin/arm64 \
        linux/386 linux/amd64 linux/arm linux/arm64 \
        windows/386 windows/amd64 windows/arm64; \
    do \
        os=$(echo "$triple" | cut -d/ -f1); arch=$(echo "$triple" | cut -d/ -f2); \
        printf "  %-18s " "$triple"; \
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build ./... 2>/dev/null && echo ok || echo FAILED; \
    done

# Build stripped, reproducible release binaries of the daemon for
# linux / darwin / windows (amd64 + arm64) into dist/. -trimpath drops local
# path prefixes; -ldflags "-s -w" strips the symbol table and DWARF for a
# smaller binary. CGo-free ⇒ no cross toolchain needed.
dist:
    @set -e; rm -rf dist; mkdir -p dist; \
    for triple in \
        linux/amd64 linux/arm64 \
        darwin/amd64 darwin/arm64 \
        windows/amd64 windows/arm64; \
    do \
        os=$(echo "$triple" | cut -d/ -f1); arch=$(echo "$triple" | cut -d/ -f2); \
        ext=""; [ "$os" = windows ] && ext=".exe"; \
        out="dist/quicsql-$os-$arch$ext"; \
        printf "  %-20s " "$triple"; \
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/quicsql; \
        echo "$out"; \
    done

# Full CI gate for this module.
ci: build test test-race lint cross-build

# Remove build artifacts.
clean:
    rm -rf dist
    go clean
