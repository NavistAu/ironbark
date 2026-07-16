# syntax=docker/dockerfile:1

# Stage 1: build a static ironbark binary.
FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /ironbark ./cmd/ironbark

# Stage 2: distroless nonroot runtime.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /ironbark /ironbark

USER nonroot

EXPOSE 8080

ENTRYPOINT ["/ironbark"]
