#!/usr/bin/env bash
# Tear down, wipe encrypted volume storage, rebuild, and cleanly boot Sovereign Vault v0.2.
#
# Usage:
#   ./scripts/rebuild_dev_vault.sh               # Clean uninitialized boot (manual CLI init)
#   ./scripts/rebuild_dev_vault.sh --auto-init   # Initialize & save keys into Ubuntu Secret Service
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRET_PY="python3 -m keyring"
AUTO_INIT="false"

for arg in "$@"; do
    case "$arg" in
        --auto-init)
            AUTO_INIT="true"
            ;;
        -h|--help)
            echo "Usage: $0 [--auto-init]"
            echo "  --auto-init   Automatically consume first-boot nonce and store unseal_key +"
            echo "                admin_token in Ubuntu Secret Service (gnome-keyring) with zero history."
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

echo "[1/4] Stopping and destroying existing sovereign-vault container..."
docker rm -f sovereign-vault >/dev/null 2>&1 || true

echo "[2/4] Deleting encrypted volume (sovereign_vault_data) for brand-new state..."
docker volume rm -f sovereign_vault_data >/dev/null 2>&1 || true

echo "[3/4] Building hardened Sovereign Vault v0.2 image & starting on 127.0.0.1:8443..."
cd "$REPO_DIR"
docker compose up -d --build

echo "[4/4] Waiting for daemon health check on https://127.0.0.1:8443/v1/sys/health..."
READY="false"
for _ in $(seq 1 30); do
    if curl -k -fsS --max-time 2 https://127.0.0.1:8443/v1/sys/health >/dev/null 2>&1; then
        READY="true"
        break
    fi
    sleep 0.5
done
if [[ "$READY" != "true" ]]; then
    echo "ERROR: Daemon health check did not respond within timeout." >&2
    docker logs sovereign-vault >&2 || true
    exit 1
fi

echo ""
echo "Health status:"
curl -k -fsS --max-time 3 https://127.0.0.1:8443/v1/sys/health && echo ""

if [[ "$AUTO_INIT" == "true" ]]; then
    echo ""
    echo "[auto-init] Extracting single-use bootstrap nonce from container logs..."
    NONCE="$(docker logs sovereign-vault 2>&1 | sed -n 's/.*Nonce: \(init_[0-9a-f]\{64\}\).*/\1/p' | tail -n 1)"
    if [[ -z "$NONCE" ]]; then
        echo "ERROR: Could not locate bootstrap nonce in container logs." >&2
        exit 1
    fi

    INIT_JSON="$(printf '%s' "$NONCE" | docker exec -i sovereign-vault sovereign-vault -k init --nonce-stdin)"
    unset NONCE

    if [[ -f "$SECRET_PY" ]]; then
        python3 -c '
import json, sys, keyring
data = json.loads(sys.stdin.read())
keyring.set_password("sovereign-vault", "unseal-key", data["unseal_key"])
keyring.set_password("sovereign-vault", "admin-token", data["admin_token"])
print("[auto-init] Stored unseal-key and admin-token (" + data["admin_token_id"] + ") in Ubuntu Secret Service (keyring).")
key = data["unseal_key"]
import requests
r = requests.post("http://127.0.0.1:8443/v1/sys/unseal", json={"unseal_key": key}, timeout=5)
if r.status_code == 200:
    print("[auto-init] Vault successfully unsealed and active!")
else:
    print(f"[auto-init] WARNING: Unseal returned status {r.status_code}: {r.text}")
' <<<"$INIT_JSON"
    else
        echo "[auto-init] WARNING: secret_service.py not found; printing bootstrap output once:"
        printf '%s\n' "$INIT_JSON"
    fi
    unset INIT_JSON

    echo "Post-init health status:"
    curl -fsS http://127.0.0.1:8443/v1/sys/health && echo ""
else
    echo ""
    echo "Vault is clean and UNINITIALIZED. To initialize interactively without shell history leakage:"
    echo "  1) Inspect nonce:  docker logs sovereign-vault | grep 'Nonce:'"
    echo "  2) Initialize:     docker exec -it sovereign-vault sovereign-vault init"
    echo "  -- OR run '$0 --auto-init' to initialize directly into Ubuntu Secret Service."
fi
