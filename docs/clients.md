# Clients

Once you have configured proxyt, you'll need to configure your client to use it.

One of the issues with client configuration is that when logging in via your SSO provider, the login URL generated still contains the tailscale.com domain, such as https://login.tailscale.com/a/something

There are several ways to solve this.

## Interactive Login

Once your proxy is running, configure Tailscale clients to use your custom domain:

```bash
tailscale login --login-server https://proxy.example.com
```

If ProxyT is fronting a custom control plane such as Headscale, the client-side command stays the same. The change is on the ProxyT side, where you set `--upstream-url https://headscale.example.com`.

Use a different device to login to Tailscale using the provider URL.

## QR code login

Use the tailscale CLI to login

```bash
tailscale up --login-server https://proxyt.example.com --qr
```

Specifying `--qr` generates a QR code you can scan with your mobile device. This will authenticate you successfully - ensure your mobile device is **not** using the same network as the Tailscale client you're trying to authenticate

## Auth Key Login

For automated deployments with pre-authorized keys:

```bash
tailscale login --login-server https://proxy.example.com --auth-key tskey-auth-xxxxx
```

## Headscale / Custom Control Plane

Example ProxyT startup for a Headscale-backed deployment:

```bash
proxyt serve \
  --domain proxy.example.com \
  --http-only \
  --port 8080 \
  --upstream-url https://headscale.example.com
```

In this mode:

- Login, registration, `/api/*`, `/machine/*`, and `/ts2021` go to your custom control server
- DERP still goes to Tailscale unless you also set `--upstream-derp-url`
