FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY . .

WORKDIR /app/certservice
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o certservice .

FROM alpine:latest
RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder /app/certservice/certservice .
RUN mkdir -p /certs
EXPOSE 8443 8080
CMD ["./certservice"]

