# Fail2Ban Dashboard Central

A central, multi-host version of [a-lang/f2b-dashboard](https://github.com/a-lang/f2b-dashboard). It retains the upstream dashboard presentation while changing the data path:

```text
remote fail2ban.log → f2b-agent (per host) → HTTPS → central API + SQLite → dashboard
```

The dashboard has an **All hosts** view and a host selector. In the all-host view, jails are prefixed with their host to avoid collisions (`web-01/sshd`).

## Central server

### Docker Compose (recommended)

The Compose stack has two containers: the unexposed dashboard/API service and
an Nginx reverse proxy. SQLite data is kept in the named `dashboard-data`
volume, so it survives container recreation.

```bash
cp .env.example .env
# edit .env and set F2B_API_TOKEN plus the initial admin password
docker compose up -d --build
docker compose ps
```

Open `http://SERVER_IP/`. Nginx is the only published service; the Python API
is available only on the internal Docker network. To build without starting:

```bash
docker build -t f2b-dashboard-central:latest .
```

The included Nginx configuration is HTTP-only for straightforward local/LAN
use. Before agents send data across an untrusted network, put this stack behind
TLS (for example, a Caddy/Traefik proxy or an Nginx `listen 443 ssl` virtual
host with your certificates) and set `F2B_CENTRAL_URL=https://...` on agents.
Never forward the event endpoint over plain Internet HTTP. Once TLS is enabled,
set `F2B_COOKIE_SECURE=true` in `.env` and restart the stack.

### Dashboard login

Authentication uses the same SQLite database as the event store. On the first
start, the service creates the initial local user from these `.env` values:

```env
F2B_ADMIN_USERNAME=admin
F2B_ADMIN_PASSWORD=use-a-unique-password-with-at-least-12-characters
```

Open the dashboard and sign in with those credentials. Passwords are stored as
salted PBKDF2-SHA256 hashes; sessions are opaque, HttpOnly, SameSite cookies
and expire after 12 hours. The user-facing dashboard APIs now require login.
Remote agents keep using `F2B_API_TOKEN` on `/api/v1/events`, independently of
dashboard login.

Create an additional dashboard user with the management command. Passwords are
environment variables rather than command-line arguments, so they do not land
in shell history:

```bash
docker compose exec \
  -e F2B_NEW_USERNAME=analyst \
  -e F2B_NEW_PASSWORD='a-unique-long-password' \
  dashboard python3 app/manage_users.py
```

Add `--reset` to replace an existing user's password. Restarting the container
does not overwrite users already stored in SQLite.

Install this repository on the central machine, choose a strong shared token, then start it behind HTTPS (Nginx/Caddy/Traefik):

```bash
sudo useradd --system --home /opt/f2b-dashboard-central --shell /usr/sbin/nologin f2bdashboard
sudo install -d -o f2bdashboard /opt/f2b-dashboard-central/data
sudo tee /etc/f2b-dashboard-central.env >/dev/null <<'EOF'
F2B_API_TOKEN=replace-with-a-long-random-secret
PORT=8080
EOF
sudo cp deploy/f2b-dashboard-central.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now f2b-dashboard-central
```

`central.py` deliberately refuses event ingestion unless `F2B_API_TOKEN` is set. Do not expose port 8080 directly to the Internet; terminate TLS in a reverse proxy and restrict `/api/v1/events` to trusted hosts/VPN where possible.

## Remote host agent

Copy `agent/f2b-agent.py` to each protected host (or keep the same repository path), then create `/etc/f2b-dashboard-agent.env`:

```bash
F2B_CENTRAL_URL=https://f2b.example.internal
F2B_API_TOKEN=replace-with-the-same-secret
```

Install and enable the supplied timer:

```bash
sudo cp deploy/f2b-dashboard-agent.service deploy/f2b-dashboard-agent.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now f2b-dashboard-agent.timer
sudo systemctl start f2b-dashboard-agent.service
```

The agent tracks its log inode and byte offset in `/var/lib/f2b-dashboard-agent/state.json`, so it only sends new records. A rotated log starts from byte zero; duplicate records are safely ignored by the central database.

## Development

```bash
F2B_API_TOKEN=development-only-token python3 app/central.py
```

Open `http://localhost:8080`. For a production deployment, use a reverse proxy with TLS, a firewall/VPN, and a different secret for every environment.

## Attribution

The `web/` dashboard assets derive from [a-lang/f2b-dashboard](https://github.com/a-lang/f2b-dashboard), licensed under MIT. This project is an architectural extension for central collection.

