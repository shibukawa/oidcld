# Compose Sample Config

Files in this directory are mounted into the `oidc.localhost` container by the repository root `compose.yaml`.

- `oidcld.yaml`
  - Main OIDCLD configuration for the Compose sample.
  - Enables EntraID-compatible behavior, the `/login` environment banner, and the default reverse proxy virtual host used by `app.localhost`.
- `login-info.md`
  - Markdown content rendered on the `/login` page.
  - Safe to edit for local links, runbooks, and environment warnings.

The Compose setup mounts this directory at `/app/config` so relative paths inside `oidcld.yaml` continue to work inside the container.
