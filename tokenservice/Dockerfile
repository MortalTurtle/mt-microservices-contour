FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY . .

WORKDIR /app/tokenservice
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o tokenservice .

FROM alpine:latest
RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder /app/tokenservice/tokenservice .
RUN mkdir -p /certs
EXPOSE 443 80
CMD ["./tokenservice"]
