#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
cd -- "$(dirname -- "$0")"
[[ $(id -u) == 0 && $# == 2 ]] || { echo "Expected root, public IPv4 and ACME email" >&2; exit 1; }
ip=$1
email=$2
state=/etc/sfera-selfhost
[[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && $email =~ ^[a-zA-Z0-9_.+%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || exit 1

. /etc/os-release
[[ $ID == debian && ( $VERSION_ID == 12 || $VERSION_ID == 13 ) || $ID == ubuntu && ( $VERSION_ID == 24.04 || $VERSION_ID == 26.04 ) ]] || {
  echo "Use Debian 12/13 or Ubuntu 24.04/26.04." >&2; exit 1;
}
[[ -c /dev/net/tun && -d /run/systemd/system ]] || { echo "systemd and /dev/net/tun are required." >&2; exit 1; }

exec 9>/run/sfera-selfhost-install.lock
flock -n 9 || { echo "Another SFERA installation is running." >&2; exit 1; }
[[ ! -e /opt/sfera/.upgrade-recovery ]] || {
  echo "An interrupted SFERA update needs recovery. Retry the update in the client." >&2; exit 1;
}
[[ ! -e /etc/systemd/system/sfera-test.service ]] || { echo "Use a VPS without the experimental SFERA deployment." >&2; exit 1; }
if [[ -f /etc/sfera-selfhost/public-ip ]]; then
  [[ $(cat /etc/sfera-selfhost/public-ip) == "$ip" ]] || { echo "SFERA is already configured for another IPv4 address." >&2; exit 1; }
  if systemctl is-active --quiet sfera-selfhost &&
     systemctl is-active --quiet nginx &&
     systemctl is-active --quiet sfera-acme.timer &&
     curl -fsS --max-time 5 --connect-to "$ip:443:127.0.0.1:443" "https://$ip/sfera-health" | grep -qx 'sfera-selfhost-v1'; then
    exit 0
  fi
else
  if [[ -n $(ss -H -ltn '( sport = :80 or sport = :443 or sport = :7443 )') ||
        -n $(ss -H -lun '( sport = :443 )') ]]; then
    echo "TCP 80, 443, 7443 and UDP 443 must be free on first installation." >&2; exit 1
  fi
fi

# Mark ownership before apt can start nginx so an interrupted install can be retried.
if command -v python3 >/dev/null; then
  python3 -c 'import ipaddress,sys; a=ipaddress.IPv4Address(sys.argv[1]); sys.exit(not a.is_global or a.is_multicast)' "$ip"
fi
install -d -m 0700 "$state"
printf '%s\n' "$ip" > "$state/public-ip"

echo "Installing system packages" >&2
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l
apt-get -q -o DPkg::Lock::Timeout=60 update >&2
apt-get -qy -o DPkg::Lock::Timeout=60 install nginx nftables iproute2 python3-venv ca-certificates curl >&2
python3 -c 'import ipaddress,sys; a=ipaddress.IPv4Address(sys.argv[1]); sys.exit(not a.is_global or a.is_multicast)' "$ip"
id sfera-selfhost >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin sfera-selfhost
# The service user must be able to traverse the parent even with umask 077.
install -d -m 0755 /opt/sfera /opt/sfera/bin /var/www/sfera-acme
install -d -m 0750 -g sfera-selfhost /etc/sfera-selfhost
printf 'SFERA_IP=%s\n' "$ip" > /etc/sfera-selfhost/server.env

install -m 0755 sfera-net /opt/sfera/bin/sfera-net
install -m 0755 sferactl.py /opt/sfera/bin/sferactl
install -m 0755 network.sh /opt/sfera/bin/network
install -m 0644 sfera-selfhost.service /etc/systemd/system/sfera-selfhost.service
/opt/sfera/bin/sferactl init >/dev/null

echo "Configuring HTTPS for the IPv4 address" >&2
config=/etc/nginx/conf.d/sfera-selfhost.conf
if [[ ! -f /etc/letsencrypt/live/sfera-selfhost/fullchain.pem ]]; then
  cat > "$config" <<EOF
server {
  listen 80;
  server_name $ip;
  location ^~ /.well-known/acme-challenge/ { root /var/www/sfera-acme; }
  location / { return 404; }
}
EOF
  nginx -t >&2
  systemctl enable --now nginx >&2
  systemctl reload nginx >&2
  python3 -m venv /opt/sfera/certbot
  /opt/sfera/certbot/bin/pip install --disable-pip-version-check 'certbot>=5.4,<6' >&2
  /opt/sfera/certbot/bin/certbot certonly --non-interactive --agree-tos --email "$email" \
    --cert-name sfera-selfhost --preferred-profile shortlived --webroot \
    --webroot-path /var/www/sfera-acme --ip-address "$ip" >&2
fi

if [[ -f $config ]]; then cp -p "$config" "$config.previous"; fi
cat > "$config" <<EOF
limit_req_zone \$binary_remote_addr zone=sfera_ip:1m rate=30r/m;
limit_req_zone \$server_name zone=sfera_total:1m rate=8r/s;
server {
  listen 80;
  server_name $ip;
  location ^~ /.well-known/acme-challenge/ { root /var/www/sfera-acme; }
  location / { return 404; }
}
server {
  listen 443 ssl;
  server_name $ip;
  ssl_certificate /etc/letsencrypt/live/sfera-selfhost/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/sfera-selfhost/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_early_data off;
  server_tokens off;
  location = /sfera-health {
    access_log off;
    default_type text/plain;
    return 200 "sfera-selfhost-v1";
  }
  location = /api/session {
    if (\$request_method != POST) { return 404; }
    access_log off;
    limit_req zone=sfera_ip burst=8 nodelay;
    limit_req zone=sfera_total burst=16 nodelay;
    limit_req_status 429;
    client_max_body_size 16k;
    client_body_timeout 5s;
    proxy_connect_timeout 2s;
    proxy_read_timeout 10s;
    proxy_send_timeout 5s;
    proxy_http_version 1.1;
    proxy_set_header Connection close;
    proxy_set_header Authorization \$http_authorization;
    proxy_pass http://127.0.0.1:7443;
  }
  location / { return 404; }
}
EOF
if ! nginx -t >&2 || ! systemctl reload nginx >&2; then
  if [[ -f $config.previous ]]; then
    mv "$config.previous" "$config"
  else
    rm -f "$config"
  fi
  exit 1
fi
rm -f "$config.previous"

cat > /etc/systemd/system/sfera-acme.service <<'EOF'
[Unit]
Description=Renew the SFERA IP certificate

[Service]
Type=oneshot
ExecStart=/opt/sfera/certbot/bin/certbot renew --cert-name sfera-selfhost --quiet --deploy-hook "/usr/bin/systemctl reload nginx"
EOF
cat > /etc/systemd/system/sfera-acme.timer <<'EOF'
[Unit]
Description=Check SFERA IP certificate renewal

[Timer]
OnCalendar=*-*-* 02,08,14,20:00:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "Starting SFERA" >&2
systemctl daemon-reload
systemctl enable --now sfera-acme.timer >&2
systemctl enable sfera-selfhost >&2
/opt/sfera/bin/sferactl apply >/dev/null

if [[ -f server-version && $(cat server-version) != unversioned ]]; then
  install -m 0644 server-version /opt/sfera/.server-version.new
  mv -f /opt/sfera/.server-version.new /opt/sfera/server-version
fi
