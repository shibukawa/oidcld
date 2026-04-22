# OIDCLD + Reverse Proxy Compose Sample

This sample uses the repository root [`compose.yaml`](/Users/shibukawayoshiki/develop/oidcld/compose.yaml) to run:

- `oidc.localhost` as the OIDCLD HTTPS issuer
- `app.localhost` as the original React/MSAL frontend served by nginx and reverse-proxied through OIDCLD
- `app2.localhost` as a second build of the same React app served directly by OIDCLD static hosting

## Start

```bash
docker compose up --build
```

## Trust The Local CA

1. Open `http://localhost:8888/console/`
2. Download the root CA from the Certificate Authority page or `http://localhost:8888/console/api/downloads/root-ca.pem`
3. Import it into your browser or OS trust store for local testing
4. The CA stays the same across restarts while the `oidcld-managed-ca` Docker volume remains

## URLs

- OIDC issuer: `https://oidc.localhost:8443`
- Developer Console + metadata companion: `http://localhost:8888/console/`
- Metadata-only HTTP endpoint: `http://localhost:8888/.well-known/openid-configuration`
- Original upstream app: `https://app.localhost:8443/`
- Static-hosted mode variant: `https://app2.localhost:8443/`

The browser-facing HTTPS listener is shared: OIDCLD terminates TLS for `oidc.localhost`, `app.localhost`, and `app2.localhost`, then applies host/path routing rules. In this sample:

- `app.localhost/` proxies the original nginx-served React app
- `app.localhost/api/*` proxies the existing Hono backend and enforces API Gateway checks
- `app2.localhost/` serves the same React app codebase from `static_dir`
- `app2.localhost/dashboard` demonstrates SPA fallback to `index.html`
- `app2.localhost/apimock/*` returns OpenAPI-backed mock responses and enforces API Gateway checks
- both app pages include links to switch to the other mode and explain which runtime topology is active

The reverse proxy configuration and request log are visible in the Developer Console.

## Login Screen Customization

The Compose sample mounts [`examples/reverseproxy/config`](/Users/shibukawayoshiki/develop/oidcld/examples/reverseproxy/config) into the OIDCLD container.

- [`oidcld.yaml`](/Users/shibukawayoshiki/develop/oidcld/examples/reverseproxy/config/oidcld.yaml) sets a blue environment banner for `/login`
- [`login-info.md`](/Users/shibukawayoshiki/develop/oidcld/examples/reverseproxy/config/login-info.md) is rendered on the login page
- [`openapi/mock.yaml`](/Users/shibukawayoshiki/develop/oidcld/examples/reverseproxy/config/openapi/mock.yaml) defines the mocked `/apimock` responses
- [`examples/azure-msal-browser-react`](/Users/shibukawayoshiki/develop/oidcld/examples/azure-msal-browser-react) is built twice:
  once for `app.localhost` through nginx and once for `app2.localhost` as static assets
- [`examples/docker-demo-api`](/Users/shibukawayoshiki/develop/oidcld/examples/docker-demo-api) remains the upstream backend used by `app.localhost/api`

Edit those files if you want different warnings, links, environment labels, or sample route behavior.
