# Configuration

Once you have installed proxyt, you can either run it directly, or host it behind a reverse proxy.

Proxyt can handle issuing a valid certificate for you via Let's Encrypt - for this to work correctly, you'll need a valid DNS entry pointing to your `domain`

## Configuration Options

All flags can be set via environment variables with the `PROXYT_` prefix (e.g., `PROXYT_DOMAIN`, `PROXYT_HTTP_ONLY`).

| Flag | Environment Variable | Description | Default | Required |
|------|---------------------|-------------|---------|----------|
| `--domain` | `PROXYT_DOMAIN` | Your custom domain name | - | Yes |
| `--email` | `PROXYT_EMAIL` | Email for Let's Encrypt registration | - | Yes (when --issue=true) |
| `--cert-dir` | `PROXYT_CERT_DIR` | Directory for SSL certificates | - | Yes (when not --http-only) |
| `--issue` | `PROXYT_ISSUE` | Auto-issue Let's Encrypt certificates | `true` | No |
| `--port` | `PROXYT_PORT` | HTTP port for challenges or main port in HTTP-only mode | `80` | No |
| `--https-port` | `PROXYT_HTTPS_PORT` | HTTPS port for the proxy | `443` | No |
| `--debug` | `PROXYT_DEBUG` | Enable debug logging | `false` | No |
| `--http-only` | `PROXYT_HTTP_ONLY` | Run behind HTTPS proxy (no TLS termination) | `false` | No |
| `--bind` | `PROXYT_BIND` | Address to bind the server to | `0.0.0.0` | No |
| `--upstream-url` | `PROXYT_UPSTREAM_URL` | Custom HTTPS control/login upstream, for example `https://headscale.example.com` | Tailscale control plane | No |
| `--upstream-derp-url` | `PROXYT_UPSTREAM_DERP_URL` | Optional custom HTTPS DERP upstream | `https://derp.tailscale.com` | No |
| `--ts2021-key-file` | `PROXYT_TS2021_KEY_FILE` | Persistent TS2021 proxy private key file for custom upstream mode | `STATE_DIRECTORY/ts2021-machine.key` or `--cert-dir/ts2021-machine.key` | Required with `--upstream-url` unless `STATE_DIRECTORY` or `--cert-dir` is available |

## Custom Upstreams

By default, Proxyt proxies to Tailscale's hosted control plane:

- Login and web flows go to `https://login.tailscale.com`
- Control plane APIs and `/ts2021` go to `https://controlplane.tailscale.com`
- DERP goes to `https://derp.tailscale.com`

If you want to front a custom control server such as Headscale, set `--upstream-url`:

```bash
proxyt serve \
  --domain proxy.example.com \
  --http-only \
  --port 8080 \
  --upstream-url https://headscale.example.com
```

With `--upstream-url` enabled:

- Login and control-plane traffic use the custom upstream
- DERP still defaults to Tailscale unless `--upstream-derp-url` is also set
- ProxyT terminates client-side TS2021 sessions locally, so it needs a stable TS2021 private key

If you run your own DERP service too:

```bash
proxyt serve \
  --domain proxy.example.com \
  --http-only \
  --port 8080 \
  --upstream-url https://headscale.example.com \
  --upstream-derp-url https://derp.example.com
```

Both upstream URLs must be `https://` URLs and must not include a path, query string, or fragment.

### TS2021 proxy key file

When `--upstream-url` is set, ProxyT acts as the TS2021 control server from the client's point of view. That means ProxyT must advertise its own `/key` public key and keep the matching private key stable across restarts.

You do not get this key file from Tailscale or Headscale. It is a local ProxyT state file:

- On first start, ProxyT creates the file automatically with a new machine private key.
- On later starts, ProxyT reads the same file and advertises the same public key.
- The file must be stored on persistent local storage and should be readable only by the ProxyT service user.
- Do not copy the upstream Headscale `noise_private.key`; ProxyT needs a separate stable key because clients that switch to the ProxyT hostname will log in against ProxyT's `/key` endpoint.

For systemd services, prefer `StateDirectory=proxyt`. systemd will create a writable persistent state directory and pass it to ProxyT as `STATE_DIRECTORY`; ProxyT will then use:

```text
$STATE_DIRECTORY/ts2021-machine.key
```

For manual or container deployments, mount a persistent directory and pass an explicit path:

```bash
proxyt serve \
  --domain proxy.example.com \
  --http-only \
  --port 8080 \
  --upstream-url https://headscale.example.com \
  --ts2021-key-file /var/lib/proxyt/ts2021-machine.key
```

Docker example:

```bash
docker run -d \
  --name proxyt \
  -p 8080:8080 \
  -v proxyt-state:/var/lib/proxyt \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve \
    --domain proxy.example.com \
    --http-only \
    --port 8080 \
    --bind 0.0.0.0 \
    --upstream-url https://headscale.example.com \
    --ts2021-key-file /var/lib/proxyt/ts2021-machine.key
```

If you run ProxyT with `--cert-dir` and do not set `--ts2021-key-file`, ProxyT can fall back to `--cert-dir/ts2021-machine.key`. For HTTP-only deployments behind a reverse proxy, set `--ts2021-key-file` or provide `STATE_DIRECTORY` explicitly.

### Migrating clients to the ProxyT hostname

Existing clients that keep using the original Headscale URL, for example `https://vpn.example.com`, continue talking directly to Headscale and do not need any ProxyT key changes.

Clients that move to the ProxyT URL, for example `https://proxy.example.com`, should create a fresh login/control-server state for that URL. They should not reuse a live session that was already connected to the old Headscale URL.

On CLI-managed clients, use a logout or force-reauth flow:

```text
tailscale up --force-reauth --login-server=https://proxy.example.com
```

On mobile clients, where daemon and CLI access is not available, use the Tailscale app UI to remove or sign out of the old Headscale profile/tailnet, then add or sign in again with the custom control server URL set to the ProxyT hostname.

## Docker

### Run with automatic certificates (requires volumes for certificate storage)

```bash
docker run -d \
  --name proxyt \
  -p 80:80 \
  -p 443:443 \
  -v proxyt-certs:/certs \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --email admin@example.com --cert-dir /certs
```

### Run in HTTP-only mode (behind reverse proxy)

If you host your own reverse proxy, or you're using funnel to expose proxyt, you'll need to run proxyt in HTTP only mode\

```bash
docker run -d \
  --name proxyt \
  -p 8080:8080 \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --http-only --port 8080 --bind 0.0.0.0
```

### With Docker Compose
```yaml
version: '3.8'
services:
  proxyt:
    image: ghcr.io/jaxxstorm/proxyt:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - proxyt-certs:/certs
    command: serve --domain proxy.example.com --email admin@example.com --cert-dir /certs
    restart: unless-stopped

volumes:
  proxyt-certs:
```

```bash
docker compose up -d
```
