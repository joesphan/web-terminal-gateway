#!/usr/bin/env bash
# Install the gateway + ttyd/tmux units on a Debian/Ubuntu host.
# Run from the checkout: sudo ./install.sh
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

SERVICE_USER="${SUDO_USER:-}"
if [[ -z "${SERVICE_USER}" || "${SERVICE_USER}" == "root" ]]; then
  echo "run this with sudo from the account that owns the terminal" >&2
  exit 1
fi
SERVICE_GROUP="$(id -gn "${SERVICE_USER}")"
SERVICE_HOME="$(getent passwd "${SERVICE_USER}" | cut -d: -f6)"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR=/opt/web-terminal-gateway
STATE_DIR=/var/lib/web-terminal-gateway
GATEWAY_PORT="${GATEWAY_PORT:-8787}"

echo "==> installing packages"
apt-get update
apt-get install -y tmux qrencode python3 curl ca-certificates
if ! command -v ttyd >/dev/null 2>&1; then
  apt-get install -y ttyd || true
fi
if ! command -v ttyd >/dev/null 2>&1; then
  case "$(uname -m)" in
    x86_64) ttyd_arch=x86_64 ;;
    aarch64 | arm64) ttyd_arch=aarch64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
  tmp="$(mktemp)"
  echo "==> downloading ttyd 1.7.7 (${ttyd_arch})"
  curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.${ttyd_arch}" -o "${tmp}"
  install -m 0755 "${tmp}" /usr/local/bin/ttyd
  rm -f "${tmp}"
fi

echo "==> installing files"
install -d -m 0755 "${INSTALL_DIR}"
install -m 0755 "${SRC}/gateway.py" "${INSTALL_DIR}/gateway.py"
install -m 0644 "${SRC}/tmux.conf" "${INSTALL_DIR}/tmux.conf"
install -d -m 0700 "${STATE_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${STATE_DIR}"

for unit in web-terminal web-terminal-gateway; do
  sed -e "s|__SERVICE_USER__|${SERVICE_USER}|g" \
      -e "s|__SERVICE_GROUP__|${SERVICE_GROUP}|g" \
      -e "s|__HOME__|${SERVICE_HOME}|g" \
      "${SRC}/systemd/${unit}.service" > "/etc/systemd/system/${unit}.service"
  chmod 0644 "/etc/systemd/system/${unit}.service"
done
sed -i "s|Environment=GATEWAY_PORT=8787|Environment=GATEWAY_PORT=${GATEWAY_PORT}|" \
  /etc/systemd/system/web-terminal-gateway.service

echo "==> enabling services"
systemctl daemon-reload
systemctl enable --now web-terminal.service web-terminal-gateway.service

LAN_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
LAN_IP="${LAN_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

cat <<EOF

Installed.

  LAN enrollment : http://${LAN_IP:-<lan-ip>}:${GATEWAY_PORT}/enroll
  Enrollment pw  : sudo cat ${STATE_DIR}/admin-password
  Terminal login : http://${LAN_IP:-<lan-ip>}:${GATEWAY_PORT}/terminal
  Services       : web-terminal.service, web-terminal-gateway.service

Enrollment and QR codes only work from the LAN. Open /enroll, sign in with the
password above, scan the QR with Microsoft Authenticator, then log in with the
6-digit code.

To expose it publicly, put a TLS tunnel in front and point it at
http://127.0.0.1:${GATEWAY_PORT} (see the Cloudflare Tunnel section in README.md).
EOF
