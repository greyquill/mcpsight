# mcpsight-index — one OCI image, runs on any container runtime.
# Multi-stage: build the static Go binary, ship it on a minimal base with the web UI.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/greyquill/mcpsight/internal/buildinfo.Version=${VERSION} -X github.com/greyquill/mcpsight/internal/buildinfo.Commit=${COMMIT}" \
    -o /out/mcpsight-index ./cmd/mcpsight-index

# Minimal runtime: a static binary on scratch. CA certs (for scan-batch's OSV /
# registry HTTPS calls) are copied from the build stage — no package manager,
# so no dependency on a reachable Alpine mirror.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/mcpsight-index /usr/local/bin/mcpsight-index
COPY web /web
ENV MCPSIGHT_WEB=/web MCPSIGHT_ADDR=:8080
EXPOSE 8080
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/mcpsight-index"]
CMD ["serve"]
