# OIDCLD 0.1.x to 0.2 Compatibility

This document summarizes the user-visible configuration changes between the latest 0.1.x line (`v0.1.8`) and the current 0.2 config model.

The source of truth for current behavior is [`internal/config/config.go`](/Users/shibukawayoshiki/.codex/worktrees/7974/oidcld/internal/config/config.go). The source of truth for the old layout in this comparison is the `v0.1.8` README / config docs and template output.

## Summary

0.2 is not a drop-in config upgrade from 0.1.x.

- The top-level `oidcld:` section was renamed to `oidc:`
- `access_filter` moved to the top level
- top-level `cors:` is no longer supported
- new top-level sections were added for `console`, `certificate_authority`, and `reverse_proxy`
- some legacy certificate-authority keys were removed in favor of `certificate_authority.domains`

## Top-Level Key Changes

| 0.1.x | 0.2 | Notes |
|---|---|---|
| `oidcld` | `oidc` | Required rename. Old `oidcld:` now fails with `ErrLegacyOIDCLDConfig`. |
| `entraid` | `entraid` | Unchanged top-level section name. |
| `autocert` | `autocert` | Unchanged section name. |
| `users` | `users` | Unchanged section name. |
| `cors` | removed | Move to `oidc.cors` or `reverse_proxy.hosts[].cors`. Old top-level `cors:` now fails with `ErrLegacyTopLevelCORS`. |
| nested `oidcld.access_filter` | `access_filter` | Moved to a top-level section. |
| not available | `console` | New in 0.2. |
| not available | `certificate_authority` | New in 0.2. |
| not available | `reverse_proxy` | New in 0.2. |

## Moved / Renamed Settings

| 0.1.x path | 0.2 path | Notes |
|---|---|---|
| `oidcld.iss` | `oidc.iss` | Same meaning, new parent section. |
| `oidcld.pkce_required` | `oidc.pkce_required` | Same meaning, new parent section. |
| `oidcld.nonce_required` | `oidc.nonce_required` | Same meaning, new parent section. |
| `oidcld.expired_in` | `oidc.expired_in` | Same meaning, new parent section. |
| `oidcld.aud_claim_format` | `oidc.aud_claim_format` | Same meaning, new parent section. |
| `oidcld.valid_scopes` | `oidc.valid_scopes` | Same meaning, new parent section. |
| `oidcld.login_ui.*` | `oidc.login_ui.*` | Same meaning, new parent section. |
| `oidcld.refresh_token_enabled` | `oidc.refresh_token_enabled` | Same meaning, new parent section. |
| `oidcld.refresh_token_expiry` | `oidc.refresh_token_expiry` | Same meaning, new parent section. |
| `oidcld.end_session_enabled` | `oidc.end_session_enabled` | Same meaning, new parent section. |
| `oidcld.end_session_endpoint_visible` | `oidc.end_session_endpoint_visible` | Same meaning, new parent section. |
| `oidcld.verbose_logging` | `oidc.verbose_logging` | Same meaning, new parent section. |
| `oidcld.tls_cert_file` | `oidc.tls_cert_file` | Same meaning, new parent section. |
| `oidcld.tls_key_file` | `oidc.tls_key_file` | Same meaning, new parent section. |
| `oidcld.access_filter.enabled` | `access_filter.enabled` | Moved to top level. |
| `oidcld.access_filter.extra_allowed_ips` | `access_filter.extra_allowed_ips` | Moved to top level. |
| `oidcld.access_filter.max_forwarded_hops` | `access_filter.max_forwarded_hops` | Moved to top level. |
| top-level `cors.enabled` | `oidc.cors` or `reverse_proxy.hosts[].cors` | 0.2 uses the `bool` or object form under the relevant section. |
| top-level `cors.allowed_origins` | `oidc.cors.origins` or `reverse_proxy.hosts[].cors.origins` | Field names changed from `allowed_origins` to `origins`. |
| top-level `cors.allowed_methods` | `oidc.cors.methods` or `reverse_proxy.hosts[].cors.methods` | Field names changed from `allowed_methods` to `methods`. |
| top-level `cors.allowed_headers` | `oidc.cors.headers` or `reverse_proxy.hosts[].cors.headers` | Field names changed from `allowed_headers` to `headers`. |

## Newly Introduced Sections in 0.2

| Section | Purpose | Key fields |
|---|---|---|
| `console` | Developer Console listener | `port`, `bind_address` |
| `certificate_authority` | Managed local development CA | `ca_dir`, `domains`, `ca_cert_ttl`, `leaf_cert_ttl` |
| `reverse_proxy` | Virtual hosts, proxying, static hosting, OpenAPI mock APIs, request log retention | `log_retention`, `ignore_log_paths`, `hosts[]` |

## Removed Legacy Keys

| Removed key | Replacement | Current behavior |
|---|---|---|
| top-level `oidcld` | `oidc`, plus top-level `access_filter`, `console`, and `certificate_authority` as needed | Current parser rejects the old top-level key. |
| top-level `cors` | `oidc.cors` or `reverse_proxy.hosts[].cors` | Current parser rejects the old top-level key. |
| `certificate_authority.domain_suffix` | `certificate_authority.domains` | Current parser rejects the old key. |
| `certificate_authority.server_names` | `certificate_authority.domains` | Current parser rejects the old key. |

## Migration Example

### 0.1.x-style snippet

```yaml
oidcld:
  iss: "https://oidc.localhost:8443"
  pkce_required: true
  access_filter:
    enabled: true
    max_forwarded_hops: 0
  login_ui:
    env_title: "Local"

cors:
  enabled: true
  allowed_origins:
    - "https://app.localhost:8443"
  allowed_methods:
    - "GET"
    - "POST"
  allowed_headers:
    - "Content-Type"
    - "Authorization"

users:
  admin:
    display_name: "Administrator"
```

### 0.2-style snippet

```yaml
access_filter:
  enabled: true
  max_forwarded_hops: 0

oidc:
  iss: "https://oidc.localhost:8443"
  pkce_required: true
  login_ui:
    env_title: "Local"
  cors:
    origins:
      - "https://app.localhost:8443"
    methods:
      - "GET"
      - "POST"
    headers:
      - "Content-Type"
      - "Authorization"

console:
  port: "18889"
  bind_address: "127.0.0.1"

certificate_authority:
  ca_dir: "./tls"
  domains:
    - "oidc.localhost"
    - "app.localhost"

users:
  admin:
    display_name: "Administrator"
```

## Operational Notes That Affect Migration

- 0.2 README examples and the Compose sample now emphasize the integrated HTTPS + console + reverse-proxy topology instead of an IdP-only topology.
- The Compose sample uses `http://localhost:18889` for the Developer Console and metadata companion, while browser-facing TLS traffic is exposed on `https://*.localhost:8443`.
- If you previously treated OIDCLD only as an IdP, you can still do that in 0.2, but old config files must still be updated to the new section layout.

## Verification Checklist

- Rename `oidcld:` to `oidc:`
- Move `access_filter` out of the OIDC section
- Replace any top-level `cors:` block with `oidc.cors` or `reverse_proxy.hosts[].cors`
- Replace legacy certificate-authority host keys with `certificate_authority.domains`
- Add `console`, `certificate_authority`, and `reverse_proxy` only if you need the new 0.2 capabilities

For the full current schema, see [docs/config.md](docs/config.md).
