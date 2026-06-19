# quicsql (quicsql.net) — common operations for the network-server nursery.
#
# A separate module (own go.mod) that pins published gosqlite.org* versions. To
# build against the sibling gosqlite checkout during co-development, run `just
# codev` (writes a gitignored go.work overlay). Install just from
# https://just.systems. Run `just` (no args) for the default gate (build + test +
# lint). Mirrors the root gosqlite justfile's shape so the two feel the same.

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
    go test -count=1 -timeout 2m -run "{{ PATTERN }}" -v ./...

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
    go test -run=^$ -bench=. -benchmem -count=3 {{ FLAGS }} ./...

# Run the daemon. Usage: just run --config quicsql.yaml
run *ARGS:
    go run ./cmd/quicsql {{ ARGS }}

# Run the self-contained example: databases across every transport, real-life

# operations, and a per-protocol throughput benchmark. Usage: just demo -dur 5s -workers 64
[doc('Self-contained demo: every transport + a per-protocol throughput benchmark')]
demo *ARGS:
    go run ./examples/demo {{ ARGS }}

# Run the auth/authz matrix demo: every authentication method and authorization

# level, with success and denial paths (exits non-zero if any expectation fails).
[doc('Auth/authz matrix over cleartext HTTP/1.1 — every method + denial paths')]
auth-demo:
    go run ./examples/auth

# Same matrix, but the credential methods (bearer/password/keyring) ride over a

# server-authenticated TLS h2 listener instead of cleartext — the deployed shape.
[doc('Auth/authz matrix with the credential methods over a TLS h2 listener')]
auth-demo-tls:
    go run ./examples/auth -tls

# Run the fully-charged deployable server: vault encryption+compression, the
# extension bundle + a custom SQL function, every transport (h2/TLS + h3/QUIC +
# dev extras), every auth method, control plane, limits, and a vault meta store.

# Usage: just charged -hosts your.host,203.0.113.10   (binds 0.0.0.0; Ctrl-C to stop)
[doc('Run the fully-charged server example (binds 0.0.0.0; Ctrl-C to stop)')]
charged *ARGS:
    go run ./examples/charged-server {{ ARGS }}

# Local end-to-end smoke, fully self-contained (no external checkout): build and
# start the in-module charged server (encryption+compression, all auth methods and
# transports, extensions, a custom SQL function), run the in-module remote tour
# against it over TLS+mTLS, then stop the server. In a real deployment the server
# runs on another host — see examples/charged-server.
[doc('Local end-to-end smoke: start the charged server, run the remote tour, stop it')]
showcase:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d)
    # Stop only the server WE started (its own PID), then reap it. No port sweeps.
    trap 'kill "${srv:-0}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$dir"' EXIT
    go build -o "$dir/charged" ./examples/charged-server
    "$dir/charged" -bind 127.0.0.1 -hosts localhost,127.0.0.1 -data "$dir/data" >"$dir/server.log" 2>&1 &
    srv=$!
    up=""
    for _ in $(seq 1 40); do curl -sf http://127.0.0.1:7775/_health >/dev/null 2>&1 && { up=1; break; }; sleep 0.25; done
    if [ -z "$up" ]; then
        echo "showcase: the charged server did not come up — ports 7775/7777 may be held by a stale run. Server log:"
        cat "$dir/server.log"
        exit 1
    fi
    go run ./examples/remote-tour -addr localhost:7777

# LiteORM Studio (browser DB admin GUI) driving a REMOTE quicSQL database. This is
# a cross-module (quicSQL + LiteORM) demo that lives in the gosqlite super-repo, so
# it only runs in the co-development checkout; it is skipped in a standalone quicSQL
# clone. When present it serves the studio at http://localhost:8088/studio/ (dev
# basic-auth admin/studio); `just studio -smoke` self-tests the API round trip.
[doc('LiteORM Studio over a remote quicSQL DB (co-dev only; skipped off-machine)')]
studio *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=../../sqlite/examples/quicsql-studio
    if [ ! -d "$dir" ]; then
        echo "studio: cross-module (quicSQL + LiteORM) demo — lives in the gosqlite super-repo"
        echo "        ($dir), not present in a standalone quicSQL checkout. Skipping."
        echo "        Run 'just showcase' for the self-contained quicSQL smoke test."
        exit 0
    fi
    (cd "$dir" && go run . {{ ARGS }})

# Lint: fmt-check + vet + staticcheck + golangci-lint + modernize (matches CI).

# fmt-check runs first — cheapest, and the most common local-only-push CI failure.
[doc('Lint: fmt-check + vet + staticcheck + golangci-lint + modernize (matches CI)')]
lint: fmt-check vet staticcheck golangci modernize

# go vet across all packages.
vet:
    go vet ./...

# staticcheck. Prefers an installed binary (PATH or GOPATH/bin), falling back to
# `go run` so the recipe never depends on what's on PATH. Install for speed:

# `go install honnef.co/go/tools/cmd/staticcheck@latest`.
[doc('Run staticcheck (prefers an installed binary, else go run)')]
staticcheck:
    @bin=$(command -v staticcheck || echo "$(go env GOPATH)/bin/staticcheck"); \
    if [ -x "$bin" ]; then "$bin" ./...; \
    else go run honnef.co/go/tools/cmd/staticcheck@latest ./...; fi

# golangci-lint (v2), pinned to the repo-root config so lint stays consistent

# with the rest of gosqlite. Same PATH-independent shape as staticcheck.
[doc('Run golangci-lint (v2), pinned to the repo config')]
golangci:
    @bin=$(command -v golangci-lint || echo "$(go env GOPATH)/bin/golangci-lint"); \
    if [ -x "$bin" ]; then "$bin" run --timeout 5m --config .golangci.yml; \
    else go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --timeout 5m --config .golangci.yml; fi

# gopls modernize: catches Go-version-bump idioms. Run via `go run` so
# contributors need no separate install. `^go: ` strips Go's auto-toolchain

# breadcrumbs (`go: downloading ...`) so they don't trip the non-empty gate.
[doc('gopls modernize: flag Go-version-bump idioms')]
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

# Co-development toggle. `just codev` writes a gitignored go.work overlay so the
# build resolves gosqlite.org* from the sibling ../../sqlite checkout instead of
# the published versions pinned in go.mod — for working on quicsql and gosqlite
# together. `just codev off` removes it (back to published gosqlite). go.mod never
# carries the replaces, so a consumer's `go get quicsql.net` just works.
[doc('Toggle the sibling-gosqlite go.work overlay for co-dev (`off` to remove)')]
codev MODE="on":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{ MODE }}" = "off" ]; then
        rm -f go.work go.work.sum
        echo "co-dev overlay removed — building against published gosqlite"
        exit 0
    fi
    [ "{{ MODE }}" = "on" ] || { echo "usage: just codev [on|off]" >&2; exit 1; }
    rm -f go.work go.work.sum
    go work init . ../../sqlite ../../sqlite/vfs/vault ../../sqlite/vfs/crypto ../../sqlite/crypto/keyring ../../sqlite/blobstore
    echo "co-dev overlay written to go.work (gitignored) — building against ../../sqlite"

# Cross-compile every package (compile-only) across the target matrix. gosqlite

# is CGo-free, so this is a pure cross-compile with no C toolchain.
[doc('Cross-compile every package across the OS/arch matrix (compile-only)')]
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
[doc('Build stripped, reproducible daemon release binaries into dist/')]
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

# Run the client-language examples (Node, Python, PHP, ...) against a scratch

# server — each asserts results, so this is a cross-SDK integration smoke test.
[doc('Cross-SDK smoke: run the client-language examples against a scratch server')]
clients-smoke:
    ./examples/clients/smoke.sh

# --- Release ---------------------------------------------------------------
# Prepare a release of the quicsql.net module: pin its gosqlite.org* requires to a
# published version, verify the module still builds, then PRINT the tag/push plan.
# It edits go.mod only — it never commits, tags, or pushes; run the printed git
# commands yourself.
#
# The local `replace` directives are dev-only and STAY: Go ignores a dependency
# module's replaces, so a consumer of quicsql.net@VERSION reads the pinned
# `require gosqlite.org@GOSQLITE` (and its vfs/vault, vfs/crypto, crypto/keyring,
# blobstore submodules) and supplies its own gosqlite — published, or its own
# replace. Because gosqlite is replaced here, pinning is a `go mod edit -require`
# (a locally-replaced module isn't hashed, so there is no go.sum to update).
#
# quicsql.net is a multi-module project, but the `quicsql.net/qsql` CLI lives in
# its OWN repo and is released from there — this recipe tags only the root module
# in this repo.
#
#   just release v0.1.0                 # tag quicsql.net@v0.1.0 (keeps the current gosqlite pin)
#   just release v0.1.0 v0.12.0         # …and pin every gosqlite.org* require to v0.12.0
#   just release v0.1.0 v0.12.0 force   # release even if nothing changed since the last tag
[doc('Pin gosqlite, verify the build, and print the tag/push plan (root module)')]
release VERSION GOSQLITE="" FORCE="":
    #!/usr/bin/env bash
    set -euo pipefail
    v='{{ VERSION }}'; gq='{{ GOSQLITE }}'; force='{{ FORCE }}'
    semver='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
    [[ "$v"  =~ $semver ]] || { echo "✗ VERSION must look like v1.2.3 or v1.2.3-rc.1 (got '$v')" >&2; exit 1; }
    [[ -z "$gq" || "$gq" =~ $semver ]] || { echo "✗ GOSQLITE must look like v1.2.3 (got '$gq')" >&2; exit 1; }
    [[ -z "$force" || "$force" == "force" ]] || { echo "✗ 3rd arg must be empty or 'force' (got '$force')" >&2; exit 1; }
    git rev-parse --git-dir >/dev/null 2>&1 || { echo "✗ not a git repo — quicsql.net is tagged in its own repo" >&2; exit 1; }
    if git rev-parse -q --verify "refs/tags/$v" >/dev/null; then echo "✗ tag $v already exists" >&2; exit 1; fi
    [ -f go.work ] && { echo "✗ a co-dev go.work overlay is active — run 'just codev off' so the release verifies against published gosqlite, not the sibling checkout" >&2; exit 1; }

    # Selective, like liteorm's release: skip when nothing changed since the last
    # tag — unless a dependency is being bumped (GOSQLITE) or 'force' is passed. A
    # never-tagged module always releases.
    last=$(git tag -l 'v*' | sort -V | tail -1)
    if [ -n "$last" ] && [ -z "$gq" ] && [ -z "$force" ] && git diff --quiet "$last" HEAD -- .; then
        echo "→ no tracked change since $last, no gosqlite bump, not forced — nothing to release."
        echo "  (pass a GOSQLITE version to bump the dep, or 'force' to re-tag anyway.)"
        exit 0
    fi
    echo "→ preparing release $v${last:+ (previous: $last)}"

    # Pin every gosqlite.org* require to GOSQLITE. `go mod edit` is a pure text edit
    # (no fetch, no go.sum) — right for these locally-replaced modules; the version
    # is what a consumer (which ignores our replaces) resolves.
    if [ -n "$gq" ]; then
        echo "→ pinning gosqlite.org* → $gq"
        for mod in $(grep -oE 'gosqlite\.org(/[A-Za-z0-9._/-]+)? v[0-9][^[:space:]]*' go.mod | sed -E 's/ v.*//' | sort -u); do
            go mod edit -require="$mod@$gq"; echo "    $mod → $gq"
        done
    fi

    echo "→ verifying the module builds (replaces resolve gosqlite locally)"
    just build

    echo
    echo "→ go.mod changes:"
    git --no-pager diff --stat -- go.mod go.sum || true

    echo
    echo "──────── RELEASE PLAN (copy/paste everything between the lines) ────────"
    echo "git add -u && git commit -m 'release $v'"
    echo "git tag $v"
    echo "git push origin HEAD --tags"
    echo "───────────────────────────────────────────────────────────────────────"
    echo
    echo "Before consumers can 'go get quicsql.net@$v', ensure:"
    echo "  • the quicsql.net go-import vanity meta is served (module path → repo)"
    [ -n "$gq" ] && echo "  • gosqlite.org@$gq — and its vfs/vault, vfs/crypto, crypto/keyring, blobstore submodules — are published tags"
    echo "  • release the quicsql.net/qsql CLI from its own repo separately, pinned to quicsql.net@$v"
