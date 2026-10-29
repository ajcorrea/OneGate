# Imagem da plataforma ONE GATE: API + painel web na mesma porta.
# Build (na raiz do repositório): docker build -f deploy/api/Dockerfile -t onegate-api .
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/onegate-api ./cmd/onegate-api \
 && mkdir -p /out/politicas

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/onegate-api /usr/local/bin/onegate-api
COPY --from=web /web/dist /srv/web
# Pasta onde o export-policy grava os pacotes assinados (até o canal seguro com o Edge existir).
COPY --from=build --chown=65532:65532 /out/politicas /politicas
ENV ONEGATE_WEB_DIR=/srv/web ONEGATE_LISTEN=:8080
USER nonroot:nonroot
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/local/bin/onegate-api"]
