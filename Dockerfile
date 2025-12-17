# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git openssl

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main cmd/main.go

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install openssl for key generation and postgresql-client for migrations
RUN apk --no-cache add openssl ca-certificates postgresql-client

# Copy binary from builder
COPY --from=builder /app/main .

# Copy migrations
COPY migrations ./migrations

# Copy templates
COPY templates ./templates

# Copy public assets
COPY --from=builder /app/public ./public

# Copy entrypoint script
COPY docker-entrypoint.sh .
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh

# Create keys directory
RUN mkdir -p /app/keys

# Expose port
EXPOSE 8080

# Use entrypoint to generate keys if needed
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["./main"]
