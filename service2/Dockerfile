FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY . .

WORKDIR /app/service2
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o service2 .

FROM alpine:latest
RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder /app/service2/service2 .
RUN mkdir -p /certs
EXPOSE 443 80
CMD ["./service2"]
