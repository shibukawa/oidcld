# OIDCLD + Managed Self-Signed TLS

This sample uses the repository root [`compose.yaml`](/Users/shibukawayoshiki/develop/oidcld/compose.yaml) to run:

- `oidc.localhost` as the OIDCLD HTTPS issuer
- `app.localhost` as the MSAL browser sample served through OIDCLD's HTTPS reverse proxy

## Start

```bash
docker compose up --build
```

## Trust The Local CA

1. Open `http://localhost:18889/console/`
2. Download the root CA from the Certificate Authority page or `http://localhost:18889/console/api/downloads/root-ca.pem`
3. Import it into your browser or OS trust store for local testing
4. The CA stays the same across restarts while the `oidcld-managed-ca` Docker volume remains

## URLs

- OIDC issuer: `https://oidc.localhost:8443`
- Developer Console + metadata companion: `http://localhost:18889/console/`
- Metadata-only HTTP endpoint: `http://localhost:18889/.well-known/openid-configuration`
- React sample app: `https://app.localhost:8443/`

The browser-facing HTTPS listener is shared: OIDCLD terminates TLS for both `oidc.localhost` and `app.localhost`, then proxies `app.localhost` traffic to the internal sample container on Docker's private network. The reverse proxy configuration and request log are visible in the Developer Console.

## Login Screen Customization

The Compose sample mounts [`examples/autocert/config`](/Users/shibukawayoshiki/develop/oidcld/examples/autocert/config) into the OIDCLD container.

- [`oidcld.yaml`](/Users/shibukawayoshiki/develop/oidcld/examples/autocert/config/oidcld.yaml) sets a blue environment banner for `/login`
- [`login-info.md`](/Users/shibukawayoshiki/develop/oidcld/examples/autocert/config/login-info.md) is rendered on the login page

Edit those files if you want different warnings, links, or environment labels.
