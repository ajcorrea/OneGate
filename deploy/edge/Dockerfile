# Imagem do Edge ONE GATE (serviço TACACS+).
# Build (na raiz do repositório): docker build -f deploy/edge/Dockerfile -t onegate-edge .
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/onegate-edge ./cmd/onegate-edge

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/onegate-edge /usr/local/bin/onegate-edge
# Sem root dentro do container: escuta na 4949 e o host publica a 49 (-p 49:4949).
USER nonroot:nonroot
VOLUME ["/etc/onegate", "/var/lib/onegate"]
EXPOSE 4949/tcp
ENTRYPOINT ["/usr/local/bin/onegate-edge"]
CMD ["serve", "--policy", "/etc/onegate/policy.json", "--listen", ":4949", "--events", "/var/lib/onegate/events.jsonl"]
