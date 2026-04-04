#!/usr/bin/env bash
# KRON Nano — One-line installer for Ubuntu 20.04+ and RHEL/AlmaLinux 8+
#
# Usage (as root):
#   curl -fsSL https://install.kron.security/nano | bash
#   # or from source:
#   bash deploy/nano/install.sh
#
# What this script does:
#   1. Detects OS (Debian/Ubuntu or RHEL/AlmaLinux)
#   2. Installs runtime dependencies (ca-certificates, libssl)
#   3. Creates kron system user and directory layout
#   4. Installs the kron-nano binary
#   5. Installs a default config to /etc/kron/kron.toml (if absent)
#   6. Installs a systemd service unit
#   7. Prints next-steps instructions

set -euo pipefail

KRON_VERSION="${KRON_VERSION:-0.1.0}"
KRON_USER="kron"
KRON_BIN="/usr/local/bin/kron-nano"
KRON_ETC="/etc/kron"
KRON_DATA="/var/lib/kron"
KRON_LOG="/var/log/kron"
SYSTEMD_UNIT="/etc/systemd/system/kron-nano.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[kron-install]${NC} $*"; }
warn()  { echo -e "${YELLOW}[kron-install] WARN:${NC} $*"; }
error() { echo -e "${RED}[kron-install] ERROR:${NC} $*" >&2; exit 1; }

# ── Root check ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "This installer must be run as root (sudo bash install.sh)"

# ── OS detection ───────────────────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_ID_LIKE="${ID_LIKE:-}"
else
    error "Cannot detect OS — /etc/os-release not found"
fi

install_deps_debian() {
    apt-get update -qq
    apt-get install -y --no-install-recommends ca-certificates libssl3 wget
}

install_deps_rhel() {
    dnf install -y ca-certificates openssl wget
}

case "$OS_ID" in
    ubuntu|debian)        install_deps_debian ;;
    rhel|almalinux|rocky) install_deps_rhel ;;
    *)
        if echo "$OS_ID_LIKE" | grep -q "debian"; then
            install_deps_debian
        elif echo "$OS_ID_LIKE" | grep -q "rhel"; then
            install_deps_rhel
        else
            warn "Unknown OS '$OS_ID' — skipping dependency install. Ensure libssl is available."
        fi
        ;;
esac

# ── System user ────────────────────────────────────────────────────────────────
if ! id "$KRON_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$KRON_USER"
    info "Created system user '$KRON_USER'"
fi

# ── Directory layout ───────────────────────────────────────────────────────────
mkdir -p \
    "$KRON_ETC/migrations" \
    "$KRON_DATA/data" \
    "$KRON_DATA/bus" \
    "$KRON_DATA/rules" \
    "$KRON_DATA/models" \
    "$KRON_DATA/archive" \
    "$KRON_LOG"

chown -R "$KRON_USER:$KRON_USER" "$KRON_DATA" "$KRON_LOG"
chmod 750 "$KRON_ETC"

# ── Binary installation ────────────────────────────────────────────────────────
if [[ -f "./target/release/kron-nano" ]]; then
    # Running from source checkout after `cargo build --release`
    cp ./target/release/kron-nano "$KRON_BIN"
    info "Installed kron-nano binary from local build"
else
    # Download pre-built binary (placeholder URL — replace with real CDN)
    DOWNLOAD_URL="https://releases.kron.security/${KRON_VERSION}/kron-nano-linux-x86_64"
    info "Downloading kron-nano ${KRON_VERSION} ..."
    wget -qO "$KRON_BIN" "$DOWNLOAD_URL" \
        || error "Download failed. Build from source: cargo build --release -p kron-nano"
fi

chmod 755 "$KRON_BIN"

# ── Default configuration ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONFIG="${SCRIPT_DIR}/kron-nano.default.toml"

if [[ ! -f "$KRON_ETC/kron.toml" ]]; then
    if [[ -f "$DEFAULT_CONFIG" ]]; then
        cp "$DEFAULT_CONFIG" "$KRON_ETC/kron.toml"
    else
        # Emit a minimal embedded config
        cat > "$KRON_ETC/kron.toml" <<'EOF'
mode = "nano"
[auth]
jwt_private_key_path = "/etc/kron/jwt.key"
jwt_public_key_path  = "/etc/kron/jwt.pub"
[api]
listen_addr = "0.0.0.0:8080"
[collector]
grpc_addr = "0.0.0.0:50051"
http_addr = "0.0.0.0:8081"
syslog_udp_addr = "0.0.0.0:514"
syslog_tcp_addr = "0.0.0.0:6514"
[normalizer]
raw_tenant_ids = []
geoip_db_path = "/var/lib/kron/GeoLite2-City.mmdb"
EOF
    fi
    info "Installed default config to $KRON_ETC/kron.toml"
else
    info "Existing config found at $KRON_ETC/kron.toml — skipping"
fi

chown root:"$KRON_USER" "$KRON_ETC/kron.toml"
chmod 640 "$KRON_ETC/kron.toml"

# ── RSA key pair (if absent) ───────────────────────────────────────────────────
if [[ ! -f "$KRON_ETC/jwt.key" ]]; then
    if command -v openssl &>/dev/null; then
        openssl genrsa -out "$KRON_ETC/jwt.key" 2048 2>/dev/null
        openssl rsa -in "$KRON_ETC/jwt.key" -pubout -out "$KRON_ETC/jwt.pub" 2>/dev/null
        chown root:"$KRON_USER" "$KRON_ETC/jwt.key" "$KRON_ETC/jwt.pub"
        chmod 640 "$KRON_ETC/jwt.key"
        chmod 644 "$KRON_ETC/jwt.pub"
        info "Generated RSA-2048 key pair for JWT signing"
    else
        warn "openssl not found — generate JWT keys manually and place them at $KRON_ETC/jwt.key and $KRON_ETC/jwt.pub"
    fi
fi

# ── systemd service ────────────────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
    cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=KRON Nano SIEM — single-binary deployment
Documentation=https://docs.kron.security/nano
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$KRON_USER
Group=$KRON_USER
ExecStart=$KRON_BIN
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

Environment=KRON_CONFIG=$KRON_ETC/kron.toml
Environment=KRON_LOG_LEVEL=info
Environment=KRON_STREAM_RULES_DIR=$KRON_DATA/rules
Environment=KRON_STREAM_MODELS_DIR=$KRON_DATA/models
Environment=KRON_STREAM_TENANT_IDS=

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$KRON_DATA $KRON_LOG
ReadOnlyPaths=$KRON_ETC

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kron-nano

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable kron-nano
    info "systemd service installed and enabled"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         KRON Nano installation complete                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
echo "  Next steps:"
echo "  1. Edit $KRON_ETC/kron.toml"
echo "     → Set normalizer.raw_tenant_ids to your tenant UUIDs"
echo "     → Configure alert.* for WhatsApp/SMS/email notifications"
echo "     → Download GeoLite2-City.mmdb to $KRON_DATA/GeoLite2-City.mmdb"
echo
echo "  2. Start the service:"
if command -v systemctl &>/dev/null; then
echo "     systemctl start kron-nano"
echo "     journalctl -u kron-nano -f"
else
echo "     KRON_CONFIG=$KRON_ETC/kron.toml $KRON_BIN"
fi
echo
echo "  3. Access the API:"
echo "     http://$(hostname -I | awk '{print $1}'):8080"
echo
