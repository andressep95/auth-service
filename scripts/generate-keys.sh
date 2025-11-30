#!/bin/bash

# Script to generate RSA key pair for JWT signing

KEYS_DIR="./keys"

# Create keys directory if it doesn't exist
mkdir -p "$KEYS_DIR"

# Generate private key
openssl genrsa -out "$KEYS_DIR/private.pem" 4096

# Generate public key from private key
openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"

# Set appropriate permissions
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/public.pem"

echo "✓ RSA keys generated successfully in $KEYS_DIR/"
echo "  - Private key: $KEYS_DIR/private.pem"
echo "  - Public key: $KEYS_DIR/public.pem"
