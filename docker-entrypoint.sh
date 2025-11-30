#!/bin/sh
set -e

echo "🔑 Checking RSA keys..."

# Paths
PRIVATE_KEY="/app/keys/private.pem"
PUBLIC_KEY="/app/keys/public.pem"

# Generate keys if they don't exist
if [ ! -f "$PRIVATE_KEY" ] || [ ! -f "$PUBLIC_KEY" ]; then
    echo "🔐 Generating RSA keys (4096 bits)..."
    
    # Generate private key
    openssl genrsa -out "$PRIVATE_KEY" 4096 2>/dev/null
    
    # Generate public key
    openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null
    
    # Set permissions
    chmod 600 "$PRIVATE_KEY"
    chmod 644 "$PUBLIC_KEY"
    
    echo "✅ RSA keys generated successfully"
else
    echo "✅ RSA keys already exist"
fi

# Execute the main command
exec "$@"
