#!/bin/sh
# deb/rpm post-install: service account and config dir for pgsafe.service.
# Config and secrets are never shipped in the package; see /usr/share/doc/pgsafe/.
set -e

if ! getent passwd pgsafe >/dev/null 2>&1; then
	useradd --system --home-dir /var/lib/pgsafe --create-home --shell /usr/sbin/nologin pgsafe 2>/dev/null ||
		useradd -r -d /var/lib/pgsafe -m -s /sbin/nologin pgsafe
fi
install -d -o pgsafe -g pgsafe -m 0700 /var/lib/pgsafe /etc/pgsafe

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi

cat <<'MSG'
pgsafe installed. To run it as a service:
  sudo install -o pgsafe -m 0600 pgsafe.yaml pgsafe.masking.yaml /etc/pgsafe/
  sudo install -o pgsafe -m 0600 /usr/share/doc/pgsafe/pgsafe.env.example /etc/pgsafe/pgsafe.env  # edit secrets
  sudo usermod -aG docker pgsafe   # only for verify.runtime: docker
  sudo systemctl enable --now pgsafe
MSG
