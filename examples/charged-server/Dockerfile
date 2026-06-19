# Container image for the fully-charged quicSQL server.
#
# This targets the RELEASED quicsql.net (published gosqlite). During local
# co-development the module's go.mod replaces gosqlite with a sibling checkout,
# which this build context does not contain — so a local `docker build` here
# fails until those replaces are dropped for a release. For a self-contained
# local container build, use the gosqlite-repo variant (examples/quicsql-charged-
# server), whose context includes gosqlite. Locally, `go run ./examples/charged-
# server` always works via the replace.
#
#   docker build -f examples/charged-server/Dockerfile -t quicsql-charged .
#   docker run --rm -p 7777:7777 -p 7777:7777/udp -v quicsql-data:/data \
#       quicsql-charged -hosts your.host.name,203.0.113.10
#
# gosqlite is CGo-free, so this is a fully static binary in a distroless image.
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
WORKDIR /src/examples/charged-server
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /charged .

FROM gcr.io/distroless/static-debian12
COPY --from=build /charged /charged
# h1 7775 (tcp), h2c 7776 (tcp), h2/TLS 7777 (tcp), h3/QUIC 7777 (udp — same port as h2).
EXPOSE 7775 7776 7777 7777/udp
VOLUME ["/data"]
ENTRYPOINT ["/charged"]
CMD ["-bind", "0.0.0.0", "-data", "/data", "-hosts", "localhost,127.0.0.1"]
