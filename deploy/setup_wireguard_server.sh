#!/usr/bin/env bash
# WireGuard server for one Windows client, on a fresh Ubuntu VM (22.04 or 24.04).
# Run as: sudo bash setup_wireguard_server.sh
# Prints the client config at the end; import it in the WireGuard app on Windows.
# Safe to re-run: existing keys and configs are kept.
set -euo pipefail

PORT=51820
NET=10.66.66
DNS=1.1.1.1

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q wireguard qrencode iptables curl

WAN=$(ip -4 route show default | awk '{print $5; exit}')
PUBLIC_IP=$(curl -4 -s --max-time 5 https://api.ipify.org || true)
[ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(ip -4 addr show "$WAN" | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')

umask 077
mkdir -p /etc/wireguard/clients
cd /etc/wireguard
[ -f server.key ] || wg genkey > server.key
wg pubkey < server.key > server.pub
[ -f clients/pc.key ] || wg genkey > clients/pc.key
wg pubkey < clients/pc.key > clients/pc.pub
[ -f clients/pc.psk ] || wg genpsk > clients/pc.psk

if [ ! -f wg0.conf ]; then
cat > wg0.conf <<EOF
[Interface]
Address = ${NET}.1/24
ListenPort = ${PORT}
PrivateKey = $(cat server.key)
PostUp = iptables -t nat -A POSTROUTING -s ${NET}.0/24 -o ${WAN} -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s ${NET}.0/24 -o ${WAN} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT

[Peer]
# pc
PublicKey = $(cat clients/pc.pub)
PresharedKey = $(cat clients/pc.psk)
AllowedIPs = ${NET}.2/32
EOF
fi

cat > clients/pc.conf <<EOF
[Interface]
PrivateKey = $(cat clients/pc.key)
Address = ${NET}.2/32
DNS = ${DNS}

[Peer]
PublicKey = $(cat server.pub)
PresharedKey = $(cat clients/pc.psk)
Endpoint = ${PUBLIC_IP}:${PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf
sysctl -q -p /etc/sysctl.d/99-wireguard.conf

# Host firewall. Oracle's Ubuntu images reject everything but SSH in iptables; ufw may be on elsewhere.
iptables -C INPUT -p udp --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport ${PORT} -j ACCEPT
command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
command -v ufw >/dev/null && ufw status | grep -q "Status: active" && ufw allow ${PORT}/udp || true

systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || systemctl restart wg-quick@wg0
wg show wg0 >/dev/null

echo
echo "WireGuard is up on ${PUBLIC_IP}:${PORT}/udp. Client config (keep it secret):"
echo "-----8<-----"
cat clients/pc.conf
echo "-----8<-----"
echo "Also make sure the cloud firewall (security list / VPC rule) allows UDP ${PORT} inbound."
