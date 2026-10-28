#!/usr/bin/env bash
# Native install on Debian/Ubuntu. Run as root from the repository root.
set -euo pipefail

# Always run relative to the project root (parent of deploy/), wherever this is called from.
cd "$(dirname "$(readlink -f "$0")")/.."
[ -d backend ] && [ -d frontend ] || { echo "backend/ or frontend/ not found in $(pwd)"; exit 1; }

apt-get update
apt-get install -y python3 python3-venv mariadb-server nginx iputils-ping

id ipam &>/dev/null || useradd --system --home /opt/ipam --shell /usr/sbin/nologin ipam
install -d -o root -g root -m 755 /opt/ipam
cp -r backend frontend /opt/ipam/
python3 -m venv /opt/ipam/venv
/opt/ipam/venv/bin/pip install --no-cache-dir -r /opt/ipam/backend/requirements.txt
chown -R root:root /opt/ipam            # code is read-only to the service user

install -d -o root -g ipam -m 750 /etc/ipam
if [ ! -f /etc/ipam/ipam.env ]; then
  DBPW=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
  KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
  cat > /etc/ipam/ipam.env <<ENV
IPAM_DB_PASSWORD=${DBPW}
IPAM_SECRET_KEY=${KEY}
ENV
  chown root:ipam /etc/ipam/ipam.env; chmod 640 /etc/ipam/ipam.env
  mariadb -e "CREATE DATABASE IF NOT EXISTS ipam CHARACTER SET utf8mb4; CREATE USER IF NOT EXISTS 'ipam'@'localhost' IDENTIFIED BY '${DBPW}'; GRANT ALL ON ipam.* TO 'ipam'@'localhost'; FLUSH PRIVILEGES;"
fi

sudo -u ipam bash -c 'set -a; . /etc/ipam/ipam.env; cd /opt/ipam/backend && /opt/ipam/venv/bin/python -m app.cli init-db'
cp deploy/ipam.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ipam

echo "Next: create the first admin:"
echo "  sudo -u ipam bash -c 'set -a; . /etc/ipam/ipam.env; cd /opt/ipam/backend && /opt/ipam/venv/bin/python -m app.cli create-admin <name>'"
echo "Then install deploy/nginx.conf, add your TLS certificate, and reload nginx."
