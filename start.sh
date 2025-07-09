#!/bin/bash

# Fail on any error
set -e

# Function to clean up on script exit
cleanup() {
    echo -e "\n[*] Cleaning up..."

    if [[ -n "$VAULT_PID" ]]; then
        echo "[*] Killing VaultServer (PID $VAULT_PID)..."
        kill "$VAULT_PID" 2>/dev/null || true
        wait "$VAULT_PID" 2>/dev/null || true
    fi

    echo "[*] Stopping NGINX..."
    sudo pkill -f nginx

    echo "[*] Checking if ports 2222 and 2223 are still bound..."
    sudo lsof -i :2222 -i :2223 || echo "[*] Ports are clean."

    echo "[✔] Cleanup complete."
}

# Trap script exit (INT = Ctrl+C, TERM = kill, EXIT = script end)
trap cleanup INT TERM EXIT

echo "[*] Starting VaultServer..."
/home/fg/Desktop/tableTopVaultServer/build/VaultServer /home/fg/Desktop/tableTopVaultServer/vault.conf &
VAULT_PID=$!

# Give VaultServer time to initialize
sleep 4

echo "[*] Starting NGINX..."
sudo /home/fg/Desktop/tableTopVaultServer/nginx-1.28.0/sbin/nginx -c /home/fg/Desktop/tableTopVaultServer/nginx/nginx.conf

echo "[✔] All services started. Press Ctrl+C to stop."

# Wait for VaultServer (or until Ctrl+C)
wait "$VAULT_PID"
