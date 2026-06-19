# syntax=docker/dockerfile:1

# Runtime image for the quicsql daemon, consumed by GoReleaser's
# prebuilt-binary docker flow: the build context is a temp directory holding
# this Dockerfile plus the already cross-compiled `quicsql` binary for the
# target platform (see `dockers:` in .goreleaser.yaml). Nothing compiles here.
#
# Base choice — gcr.io/distroless/static-debian12:nonroot over alpine:
# the binary is CGo-free and fully static, so it needs no libc and no shell;
# distroless ships exactly what the server does need at runtime — CA
# certificates for outbound TLS, tzdata, and a nonroot (65532) user — with no
# package manager or shell as attack surface, and none of alpine's
# musl-vs-glibc considerations. The cost (no shell for debugging) is the point.
FROM gcr.io/distroless/static-debian12:nonroot

COPY quicsql /usr/local/bin/quicsql

# Writable data directory for databases / vault containers. WORKDIR both
# creates the directory and — under BuildKit, which the buildx flow guarantees
# — creates it owned by the active (nonroot) user. That is the way to get a
# nonroot-writable dir in a shell-less image without an extra build stage
# (no RUN mkdir/chown is possible here). Bonus: relative database paths in the
# config resolve under /data.
WORKDIR /data
VOLUME /data

# Canonical transport ports (AGENTS.md): 7775 h1, 7776 h2c, 7777 h2/TLS. h3/QUIC
# shares 7777 — QUIC is UDP, a separate namespace from h2's TCP (as HTTPS shares
# :443), so 7777 is exposed on both protocols.
EXPOSE 7775-7777/tcp
EXPOSE 7777/udp

ENTRYPOINT ["quicsql"]
# Default config location; mount yours there
#   docker run -v ./quicsql.yaml:/etc/quicsql/quicsql.yaml:ro ...
# or override CMD with a different --config path.
CMD ["--config", "/etc/quicsql/quicsql.yaml"]

# ---------------------------------------------------------------------------
# Standalone from-source variant (commented out). Build with a plain
# `docker build .` once go.mod no longer carries the local
# `replace … => ../../sqlite` directives — until then the builder stage cannot
# resolve gosqlite.org from a checkout of this repo alone, so it is disabled
# rather than shipping a build that fails for everyone.
#
# FROM golang:1.26-alpine AS build
# WORKDIR /src
# COPY go.mod go.sum ./
# RUN go mod download
# COPY . .
# RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/quicsql ./cmd/quicsql
#
# FROM gcr.io/distroless/static-debian12:nonroot
# COPY --from=build /out/quicsql /usr/local/bin/quicsql
# WORKDIR /data
# VOLUME /data
# EXPOSE 7775-7777/tcp
# EXPOSE 7777/udp
# ENTRYPOINT ["quicsql"]
# CMD ["--config", "/etc/quicsql/quicsql.yaml"]
# ---------------------------------------------------------------------------
