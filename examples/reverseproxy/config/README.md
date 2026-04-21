# Compose Sample Config

Files in this directory are mounted into the `oidc.localhost` container by the repository root `compose.yaml`.

- `oidcld.yaml`
  - Main OIDCLD configuration for the Compose sample.
  - Enables EntraID-compatible behavior, the `/login` environment banner, and the Virtual Host rules used by `app.localhost` and `app2.localhost`.
- `login-info.md`
  - Markdown content rendered on the `/login` page.
  - Safe to edit for local links, runbooks, and environment warnings.
- `openapi/mock.yaml`
  - OpenAPI document used by the `/apimock` mock route.
  - The route is protected by API Gateway checks in `oidcld.yaml`.
- `app.localhost`
  - Existing React/MSAL frontend proxied through OIDCLD, with `/api` routed to the Hono demo backend.
- `app2.localhost`
  - Second build of the same React app served by OIDCLD static hosting from a compose-managed build artifact volume.

The Compose setup mounts this directory at `/app/config` so relative paths inside `oidcld.yaml` continue to work inside the container.
