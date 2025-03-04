#!/bin/sh

# Wait for any dependencies
sleep 5

# Start the certificate manager
exec python3 /app/scripts/cert_manager.py