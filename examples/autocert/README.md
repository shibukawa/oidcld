# OIDCLD + ACME Auto Cert

This sample uses the repository root [`compose.yaml`](/Users/shibukawayoshiki/develop/oidcld/compose.yaml) to run:

- `myencrypt.localhost` as a local ACME server
- `oidc.localhost` as the OIDCLD HTTPS issuer
- `app.localhost` as the MSAL browser sample

## Start

```bash
docker compose up --build
```

## Trust The Local CA

1. Open `http://localhost:14000/download`
2. Download `rootCA.pem`
3. Import it into your browser or OS trust store for local testing

## URLs

- OIDC issuer: `https://oidc.localhost:8443`
- Metadata-only HTTP endpoint: `http://localhost:18888`
- React sample app: `http://app.localhost:3000/`
- ACME helper UI: `http://localhost:14000/download`

## Login Screen Customization

The Compose sample mounts [`examples/autocert/config`](/Users/shibukawayoshiki/develop/oidcld/examples/autocert/config) into the OIDCLD container.

- [`oidcld.yaml`](/Users/shibukawayoshiki/develop/oidcld/examples/autocert/config/oidcld.yaml) sets a blue environment banner for `/login`
- [`login-info.md`](/Users/shibukawayoshiki/develop/oidcld/examples/autocert/config/login-info.md) is rendered on the login page

Edit those files if you want different warnings, links, or environment labels.
