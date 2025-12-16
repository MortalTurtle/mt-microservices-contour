FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY . .

WORKDIR /app/service1
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o service1 .

FROM alpine:latest
RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder /app/service1/service1 .
RUN mkdir -p /certs
EXPOSE 443 80
CMD ["./service1"]
