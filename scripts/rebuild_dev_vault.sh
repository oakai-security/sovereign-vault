#!/usr/bin/env bash
# Tear down, wipe encrypted volume storage, rebuild, and cleanly boot Sovereign Vault v1.0.
#
# Usage:
#   ./scripts/rebuild_dev_vault.sh               # Clean uninitialized boot (manual CLI init)
#   ./scripts/rebuild_dev_vault.sh --auto-init   # Initialize & save keys into Ubuntu Secret Service
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTO_INIT="false"

for arg in "$@"; do
    case "$arg" in
        --auto-init)
            AUTO_INIT="true"
            ;;
        -h|--help)
            echo "Usage: $0 [--auto-init]"
            echo "  --auto-init   Automatically consume /data/.bootstrap_nonce and store unseal_key +"
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

echo "[3/4] Building hardened Sovereign Vault v1.0 image & starting on 127.0.0.1:8443..."
cd "$REPO_DIR"
docker compose up -d --build

CA_PIN_FILE="$(mktemp)"
trap 'rm -f "$CA_PIN_FILE"' EXIT

echo "[4/4] Pinning autonomous TLS 1.3 certificate and waiting for health check..."
READY="false"
for _ in $(seq 1 30); do
    if docker exec sovereign-vault cat /data/tls/cert.pem >"$CA_PIN_FILE" 2>/dev/null && [[ -s "$CA_PIN_FILE" ]]; then
        if curl --cacert "$CA_PIN_FILE" --tlsv1.3 -fsS --max-time 2 https://127.0.0.1:8443/v1/sys/health >/dev/null 2>&1; then
            READY="true"
            break
        fi
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
curl --cacert "$CA_PIN_FILE" --tlsv1.3 -fsS --max-time 3 https://127.0.0.1:8443/v1/sys/health && echo ""

if [[ "$AUTO_INIT" == "true" ]]; then
    echo ""
    echo "[auto-init] Reading single-use bootstrap nonce from /data/.bootstrap_nonce..."
    NONCE="$(docker exec sovereign-vault cat /data/.bootstrap_nonce 2>/dev/null | tr -d '\r\n')"
    if [[ -z "$NONCE" ]]; then
        echo "ERROR: Could not read /data/.bootstrap_nonce inside container." >&2
        exit 1
    fi

    INIT_JSON="$(printf '%s' "$NONCE" | docker exec -i sovereign-vault sovereign-vault --ca-cert /data/tls/cert.pem init --nonce-stdin)"
    unset NONCE

    if python3 -c 'import keyring' >/dev/null 2>&1; then
        CA_PIN_PATH="$CA_PIN_FILE" python3 -c '
import json, os, ssl, sys, urllib.request, keyring
data = json.loads(sys.stdin.read())
keyring.set_password("sovereign-vault", "unseal-key", data["unseal_key"])
keyring.set_password("sovereign-vault", "admin-token", data["admin_token"])
print("[auto-init] Stored unseal-key and admin-token (" + data["admin_token_id"] + ") in OS Keyring.")
ctx = ssl.create_default_context(cafile=os.environ["CA_PIN_PATH"])
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
req = urllib.request.Request(
    "https://127.0.0.1:8443/v1/sys/unseal",
    data=json.dumps({"unseal_key": data["unseal_key"]}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
    if resp.status == 200:
        print("[auto-init] Vault successfully unsealed and active over pinned TLS 1.3!")
    else:
        print(f"[auto-init] WARNING: Unseal returned status {resp.status}")
' <<<"$INIT_JSON"
    else
        echo "[auto-init] python keyring library not detected; printing bootstrap output once:"
        printf '%s\n' "$INIT_JSON"
    fi
    unset INIT_JSON

    echo "Post-init health status:"
    curl --cacert "$CA_PIN_FILE" --tlsv1.3 -fsS https://127.0.0.1:8443/v1/sys/health && echo ""
else
    echo ""
    echo "Vault is clean and UNINITIALIZED. To initialize interactively without shell history or stdout leakage:"
    echo "  1) Read nonce:  docker exec sovereign-vault cat /data/.bootstrap_nonce"
    echo "  2) Initialize:  docker exec -it sovereign-vault sovereign-vault --ca-cert /data/tls/cert.pem init"
    echo "  -- OR run '$0 --auto-init' to initialize directly into Ubuntu Secret Service."
fi
