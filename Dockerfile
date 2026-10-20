FROM docker.io/library/node:24-bookworm-slim@sha256:6642ef280aebc09c4541bee0b15c9f89f0f3f3c247ddee79ae1d37eddfdcbbaa AS web
WORKDIR /build/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build
FROM docker.io/library/golang:1.27.2-bookworm@sha256:55395706e9703db746cc507abfc4eb2aea75918f8a8024e4848e2cb81004f5ad AS go
ARG GOFIPS140=v1.0.0
ARG VERSION=0.1.0-dev
ENV GOFIPS140=$GOFIPS140
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-X main.version=${VERSION}" -o /nebulalog ./cmd/nebulalog
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --no-create-home nebulalog
WORKDIR /app
COPY --from=go /nebulalog /usr/local/bin/nebulalog
COPY --from=web /build/web/dist /app/web
RUN find /app/web -type d -exec chmod 0755 {} + && find /app/web -type f -exec chmod 0644 {} +
COPY migrations /app/migrations
COPY LICENSE /app/LICENSE
LABEL org.opencontainers.image.licenses="AGPL-3.0-only AND LicenseRef-Debian-Component-Licenses"
USER 10001
ENV WEB_DIR=/app/web API_LISTEN=:8080 SPOOL_DIR=/var/lib/nebulalog/spool EXPORT_DIR=/var/lib/nebulalog/exports
EXPOSE 8080 5514/tcp 5514/udp 6514/tcp
ENTRYPOINT ["nebulalog"]
CMD ["all"]
