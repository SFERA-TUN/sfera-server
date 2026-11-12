#!/usr/bin/env bash
set -euo pipefail

STATE_DIR=/var/lib/sfera-test-host
SYSCTL_FILE=/etc/sysctl.d/90-sfera-test.conf
TABLE=inet
TABLE_NAME=sfera_test
if [[ ${1:-} == --selfhost ]]; then
  STATE_DIR=/var/lib/sfera-selfhost-network
  SYSCTL_FILE=/etc/sysctl.d/90-sfera-selfhost.conf
  TABLE_NAME=sfera_selfhost
  shift
fi

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
  fi
}

up() {
  require_root
  local public_iface original_forward nft_file tunnels peers gateways entries peer gateway iface sep=
  local index=0
  public_iface=$(ip -o route get 1.1.1.1 | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
  if [[ ! $public_iface =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; then
    echo "could not determine the public IPv4 interface" >&2
    exit 1
  fi

  if [[ $# -eq 1 ]]; then
    if [[ ! -f $1 ]] || (( $(wc -c <"$1") > 4096 )); then
      echo "invalid SFERA credentials file" >&2
      return 1
    fi
    entries=$(awk '
      { sub(/\r$/, "") }
      NF == 0 { next }
      {
        if (NF != 2 || length($2) != 64 || $2 ~ /[^a-f0-9]/ || seen[$1]++ || ++count > 16 ||
            split($1, ip, /\./) != 4) exit 1
        for (i = 1; i <= 4; i++)
          if (ip[i] !~ /^(0|[1-9][0-9]?[0-9]?)$/ || ip[i] + 0 > 255) exit 1
        if (!(ip[1] == 10 || (ip[1] == 172 && ip[2] >= 16 && ip[2] <= 31) ||
              (ip[1] == 192 && ip[2] == 168)) || ip[4] % 4 != 2) exit 1
        printf "%s %d.%d.%d.%d\n", $1, ip[1], ip[2], ip[3], ip[4] - 1
      }
      END { if (!count) exit 1 }
    ' "$1") || { echo "invalid SFERA peer entries" >&2; return 1; }
  else
    entries="10.203.0.2 10.203.0.1"
  fi
  # Use the same numeric IPv4 order as the server when assigning TUN names.
  entries=$(printf '%s\n' "$entries" | LC_ALL=C sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
  tunnels=
  for ((index = 0; index < 16; index++)); do
    tunnels+="$sep\"sfera$index\""
    sep=', '
  done
  index=0
  sep=
  peers=
  gateways=
  while read -r peer gateway; do
    iface="\"sfera$index\""
    peers+="$sep$iface . $peer"
    gateways+="$sep$iface . $peer . $gateway"
    index=$((index + 1))
    sep=', '
  done <<<"$entries"

  install -d -o root -g root -m 0700 "$STATE_DIR"
  if [[ ! -e "$STATE_DIR/original-ip-forward" ]]; then
    original_forward=$(sysctl -n net.ipv4.ip_forward)
    printf '%s\n' "$original_forward" >"$STATE_DIR/original-ip-forward"
    chmod 0600 "$STATE_DIR/original-ip-forward"
  fi

  nft_file=$(mktemp)
  trap 'rm -f "$nft_file"' EXIT
  if nft list table "$TABLE" "$TABLE_NAME" >/dev/null 2>&1; then
    printf 'delete table %s %s\n' "$TABLE" "$TABLE_NAME" >"$nft_file"
  fi
  cat >>"$nft_file" <<EOF
table inet $TABLE_NAME {
  set tunnels {
    type ifname
    elements = { $tunnels }
  }

  set peers {
    type ifname . ipv4_addr
    elements = { $peers }
  }

  set gateways {
    type ifname . ipv4_addr . ipv4_addr
    elements = { $gateways }
  }

  chain input {
    type filter hook input priority -20; policy accept;
    iifname . ip saddr . ip daddr @gateways ip protocol icmp icmp type echo-request counter accept
    iifname @tunnels counter drop
  }

  chain forward {
    type filter hook forward priority -20; policy accept;
    iifname @tunnels ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } counter drop
    iifname . ip saddr @peers oifname "$public_iface" counter accept
    oifname . ip daddr @peers ct state established,related counter accept
    iifname @tunnels counter drop
    oifname @tunnels counter drop
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    iifname . ip saddr @peers oifname "$public_iface" counter masquerade
  }
}
EOF
  nft --check -f "$nft_file"
  nft -f "$nft_file"
  printf 'net.ipv4.ip_forward=1\n' >"$SYSCTL_FILE"
  chmod 0644 "$SYSCTL_FILE"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  trap - EXIT
  rm -f "$nft_file"
  echo "SFERA test forwarding enabled on $index TUN interfaces via $public_iface"
}

down() {
  require_root
  nft delete table "$TABLE" "$TABLE_NAME" 2>/dev/null || true
  rm -f "$SYSCTL_FILE"
  if [[ -r "$STATE_DIR/original-ip-forward" ]]; then
    local original_forward
    original_forward=$(cat "$STATE_DIR/original-ip-forward")
    if [[ $original_forward == 0 || $original_forward == 1 ]]; then
      sysctl -w "net.ipv4.ip_forward=$original_forward" >/dev/null
      if [[ $TABLE_NAME == sfera_selfhost ]]; then rm -f "$STATE_DIR/original-ip-forward"; fi
    else
      echo "saved IPv4 forwarding state is invalid; leaving current value unchanged" >&2
      return 1
    fi
  fi
  echo "SFERA test forwarding removed"
}

case "${1:-}:$#" in
  up:1|up:2) shift; up "$@" ;;
  down:1) down ;;
  *) echo "usage: $0 up [PEER_CREDENTIALS] | down" >&2; exit 2 ;;
esac
