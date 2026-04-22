# OIDCLD

Local development identity, TLS, and edge routing in one runtime.

[![CI](https://github.com/shibukawa/oidcld/actions/workflows/ci.yml/badge.svg)](https://github.com/shibukawa/oidcld/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/shibukawa/oidcld)](https://github.com/shibukawa/oidcld/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shibukawa/oidcld)](go.mod)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE.md)
[![Container](https://img.shields.io/badge/GHCR-oidcld-0f5fff?logo=docker)](https://github.com/shibukawa/oidcld/pkgs/container/oidcld)

Japanese: see [README.ja.md](README.ja.md)

Quick links: [Configuration Guide](docs/config.md) | [0.1.x to 0.2 Compatibility](COMPATIBILITY.md) | [llms.txt](llms.txt)

OIDCLD started as a fake OpenID Connect Identity Provider for testing. In 0.2, it is better described as a local development edge platform: it can act as an OIDC / EntraID-compatible IdP, manage a local development CA, terminate TLS for multiple hosts, reverse proxy frontend and API traffic, serve static assets, return OpenAPI-backed mock responses, and expose a developer console with reverse-proxy logs.

This project is still for development and testing only. Do not use it in production.

![console](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/console.png)

## Full Stack Topology

![OIDCLD full stack topology](docs/oidcld-components.svg)

The diagram shows the full 0.2 shape: browser traffic reaches OIDCLD as both an identity provider and an edge router, OIDC-issued tokens can be validated at reverse-proxy routes, and the managed local CA covers the browser-facing hosts. In the integrated Compose sample, `oidc.localhost`, `app.localhost`, and `app2.localhost` share the HTTPS listener on container port `443`, exposed as host port `8443`, while the Developer Console and metadata companion use a separate listener on `8888`.

If you enable split listener mode with `--proxy-port` or `PROXY_PORT`, the same topology still applies logically, but OIDC and reverse-proxy traffic are exposed on separate browser-facing ports instead of sharing one listener.

## What OIDCLD Is Now

OIDCLD 0.2 has three primary roles:

### 1. OIDC / EntraID-compatible identity provider

- Supports Authorization Code, Client Credentials, Device Flow, refresh tokens, PKCE, and RP-initiated logout
- Exposes standards-compliant OIDC discovery and JWKS endpoints
- Can emulate EntraID / Azure-style claims and endpoint aliases for MSAL integration
- Keeps the fast developer login model: select a user instead of typing passwords

### 2. Managed local CA and TLS tooling

- Generates and persists a local development root CA under `certificate_authority.ca_dir`
- Issues leaf certificates for the OIDC issuer host and reverse-proxy hosts
- Provides root CA downloads and install / uninstall scripts from the Developer Console
- Can also use manual TLS cert files or `autocert` when you need a different HTTPS path

### 3. Reverse proxy, static hosting, and mock APIs

- Routes by virtual host and path via `reverse_proxy.hosts[]`
- Proxies frontend and backend traffic to upstream services
- Serves static assets with optional SPA fallback
- Returns OpenAPI-backed mock responses
- Enforces route-level API gateway checks against OIDCLD-issued bearer tokens
- Shows reverse-proxy configuration and request logs in the Developer Console

## Quick Start Options

### Simple local OIDC server

Use the binary directly when you only need a local IdP.

```bash
./oidcld init
./oidcld
open http://localhost:8080/.well-known/openid-configuration
```

By default this starts the HTTP listener on `8080`. Add `--cert-file` / `--key-file` later if you want manual HTTPS.

### Managed local TLS + developer console

Use `certificate_authority` and `console` in `oidcld.yaml` when you want OIDCLD to manage local certificates and expose console tooling. Listener ports are controlled at runtime with `--port`, `PORT`, `--console-port`, and `CONSOLE_PORT`. When `access_filter` is omitted, OIDCLD defaults it to `true` on the host and `false` in detected container runtimes; explicit `access_filter` settings are preserved.

Discovery keeps `issuer` fixed to `oidc.iss`, but the public endpoint URLs it returns follow the request host. That lets browsers use `https://oidc.localhost:8443` while container clients can consume metadata from `http://oidcld:8888`.

```yaml
access_filter:
  enabled: true

oidc:
  iss: "https://oidc.localhost:8443"
  pkce_required: true
  login_ui:
    env_title: "Local Compose"
    info_markdown_file: "./login-info.md"
  cors: true

console:
  bind_address: "127.0.0.1"

certificate_authority:
  ca_dir: "./tls"
  domains:
    - "oidc.localhost"
    - "app.localhost"
    - "app2.localhost"
```

This mode is the basis for the full-stack sample described below.

## Integrated Compose Sample

The repository root [`compose.yaml`](/Users/shibukawayoshiki/.codex/worktrees/7974/oidcld/compose.yaml) and [`examples/reverseproxy/config/oidcld.yaml`](/Users/shibukawayoshiki/.codex/worktrees/7974/oidcld/examples/reverseproxy/config/oidcld.yaml) demonstrate the 0.2 integrated topology:

- One HTTPS listener on container port `443`, exposed as `https://*.localhost:8443`
- One separate Developer Console and metadata companion listener on `http://localhost:8888`
- `app.localhost` reverse proxies an upstream-built frontend and `/api/*` backend
- `app2.localhost` serves static files directly from OIDCLD and maps `/apimock/*` to OpenAPI mocks
- The local CA persists in the `oidcld-managed-ca` volume, so the root CA remains stable across restarts while the volume exists

Start it with:

```bash
docker compose up --build
```

Then use:

- OIDC issuer: `https://oidc.localhost:8443`
- Reverse-proxied frontend: `https://app.localhost:8443`
- Static-hosted frontend: `https://app2.localhost:8443`
- Developer Console: `http://localhost:8888/console/`

The console lets you download the root CA and inspect reverse-proxy routes and request logs. The sample is also documented in [examples/reverseproxy/README.md](examples/reverseproxy/README.md).

If you cannot rely on wildcard `*.localhost` resolution, use split listener mode:

```bash
./oidcld serve --port 8443 --proxy-port 19080
```

In that mode, `--port` or `PORT` stays the OIDC listener and `--proxy-port` or `PROXY_PORT` becomes the dedicated reverse-proxy listener. `--console-port` or `CONSOLE_PORT` controls the optional third browser-facing port for the Developer Console and metadata companion. If neither `--proxy-port` nor `PROXY_PORT` is set, reverse proxy shares the main listener.

## EntraID Compatibility

OIDCLD can emulate Azure AD / EntraID behavior for MSAL-driven local development.

- Use `./oidcld init --template entraid-v2` to scaffold an EntraID-flavored config
- EntraID modes set the appropriate issuer shape and Azure-style claim layout
- `aud_claim_format: string` remains the default for single-audience EntraID-style output
- Microsoft-style aliases such as `/{tenant}/v2.0/.well-known/openid-configuration` are supported
- HTTPS is required for realistic MSAL browser testing

Minimal example:

```bash
./oidcld init --template entraid-v2
./oidcld --cert-file localhost.pem --key-file localhost-key.pem
curl -k https://localhost:8443/.well-known/openid-configuration
```

## Configuration Notes

OIDCLD 0.2 uses the current config model:

- `oidc:` is the OIDC / IdP section
- `access_filter:` is a top-level section
- `oidc.cors` configures CORS for IdP endpoints
- `reverse_proxy.hosts[].cors` configures CORS for reverse-proxy hosts
- `console`, `certificate_authority`, and `reverse_proxy` are top-level sections

If you are migrating from 0.1.x, read [COMPATIBILITY.md](COMPATIBILITY.md) before reusing an older config file.

## CLI Summary

- `oidcld init`: scaffold a config from a template
- `oidcld serve`: start the runtime
- `oidcld serve --proxy-port <port>`: split OIDC and reverse proxy onto separate browser-facing listeners (`PROXY_PORT` is the env equivalent)
- `oidcld health`: probe readiness / liveness
- `oidcld mcp`: run the MCP server mode

See [docs/config.md](docs/config.md) for full flags, env vars, defaults, and runtime behavior.

## Security Limitations

OIDCLD deliberately trades security strictness for local development speed.

- `client_id` values are not allowlisted
- `redirect_uri` values are accepted dynamically
- client secrets are not enforced
- signing keys are generated on startup and not persisted
- local-only access rules are applied by `access_filter`
- permissive CORS defaults exist to simplify SPA development

These behaviors are intentional for development and testing, not production use.

## Documentation

- [Configuration Guide](docs/config.md)
- [0.1.x to 0.2 Compatibility](COMPATIBILITY.md)
- [Other OAuth / OIDC Flows](docs/otherflows.md)
- [examples/reverseproxy/README.md](examples/reverseproxy/README.md)

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
