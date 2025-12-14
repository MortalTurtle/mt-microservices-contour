FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY . .

WORKDIR /app/gate
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o gate .

FROM alpine:latest
RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder /app/gate/gate .
RUN mkdir -p /certs
EXPOSE 443 80
CMD ["./gate"]
