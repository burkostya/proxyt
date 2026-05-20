# Architecture

The proxy intelligently routes requests based on path patterns and headers:

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────────────┐
│  Tailscale      │    │   ProxyT     │    │     Tailscale Cloud     │
│  Client/Browser │───▶│   Proxy      │───▶│                         │
│                 │    │              │    │ ┌─────────────────────┐ │
└─────────────────┘    └──────────────┘    │ │ login.tailscale.com │ │
                                           │ │ controlplane.ts.com │ │
                                           │ │ derp.tailscale.com  │ │
                                           │ └─────────────────────┘ │
                                           └─────────────────────────┘
```

When `--upstream-url` is configured, ProxyT keeps the same routing logic but swaps the login and control-plane destinations to your custom upstream. DERP continues to use `derp.tailscale.com` unless `--upstream-derp-url` is set.

## Request Routing Logic

- **Control Protocol** (`/ts2021`): Custom protocol upgrade handler for the configured control-plane upstream
- **Key Exchange** (`/key`): Routes to the configured control-plane upstream
- **API Endpoints** (`/api/*`, `/machine/*`): Routes to the configured control-plane upstream
- **DERP Traffic** (`/derp/*`): Routes to the configured DERP upstream, defaulting to `derp.tailscale.com`
- **Authentication** (`/login`, `/auth`, `/a/*`): Routes to the configured login upstream
- **Default/Web**: Routes to the configured login upstream

### Logging

Structured JSON logging (production) or console logging (debug mode):

```json
{
  "level": "info",
  "ts": "2025-07-16T13:35:12.123Z",
  "msg": "Reverse proxying request",
  "host": "proxy.example.com",
  "path": "/key",
  "target": "control"
}
```
