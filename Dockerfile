FROM golang:1.25-alpine AS builder
WORKDIR /build

# Копируем exchange-shared (для replace директивы)
COPY exchange-shared/ exchange-shared/

# Копируем auth-service
COPY auth-service/go.mod auth-service/go.sum auth-service/
WORKDIR /build/auth-service
RUN go mod download

COPY auth-service/ /build/auth-service/
RUN go build -o auth-service ./cmd/main.go

FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY --from=builder /build/auth-service/auth-service /app/auth-service
COPY auth-service/config.yaml /app/config.yaml
COPY auth-service/migrations /app/migrations

EXPOSE 50053

ENTRYPOINT ["/app/auth-service"]
