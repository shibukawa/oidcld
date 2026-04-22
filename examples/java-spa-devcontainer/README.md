# Java SPA Dev Container Example

This example runs the infrastructure with Docker Compose and runs the application processes manually inside a dev container:

- `oidcld` for local OIDC and reverse proxy
- `postgres` as a companion service for future expansion
- `Quarkus` as a Resource Server with in-memory CRUD
- `Vue` as the browser app using Authorization Code Flow

`postgres` is started but unused in this v1 example. CRUD data lives only in the Quarkus process and resets when Quarkus restarts.

## Topology

- Browser entrypoint: `https://app.localhost:8443`
- OIDC issuer: `https://oidc.localhost:8443`
- Developer Console: `http://localhost:8888/console/`
- Quarkus backend in dev container: `http://workspace:8080`
- Vue dev server in dev container: `http://workspace:5173`

`oidcld`, `postgres`, and the `workspace` dev container run in the same Compose project. `oidcld` reverse-proxies browser traffic to the `workspace` service.

## Start

Open this example in a dev container. The dev container starts:

- `oidcld`
- `postgres`
- `workspace`

It uses [`.devcontainer/devcontainer-compose.yaml`](/Users/shibukawayoshiki/.codex/worktrees/896f/oidcld/examples/java-spa-devcontainer/.devcontainer/devcontainer-compose.yaml) and pulls `ghcr.io/shibukawa/oidcld:v0.2.0`.

Inside the dev container, install dependencies and start both app processes:

```bash
cd backend
mvn quarkus:dev
```

In another terminal inside the same dev container:

```bash
cd frontend
npm install
npm run dev
```

## Trust The Local CA

1. Open `http://localhost:8888/console/`
2. Download the root CA from the Certificate Authority page
3. Import it into your browser or OS trust store
4. Visit `https://app.localhost:8443`

The managed CA is persisted in the `oidcld-managed-ca` volume, so the certificate remains stable until you remove the volume.

## What To Verify

1. Sign in as `editor` to test full CRUD
2. Open the profile panel and confirm `/api/me` returns claims and scopes
3. Create, update, and delete items from the UI
4. Restart Quarkus and confirm the list resets to the seeded in-memory items
5. Sign in as `reviewer` and confirm reads still work but writes fail with `403`

## Notes

- Quarkus uses `http://oidcld:8888` inside the shared Compose network. Do not use a `.localhost` hostname for container-to-container traffic, because `.localhost` resolves to loopback inside the dev container.
- The browser still talks to `https://oidc.localhost:8443`, so local CA trust is required on the host.
- This sample disables `access_filter` by default, because browser traffic often arrives from non-local Docker bridge addresses during devcontainer use.
- If you re-enable `access_filter` and `https://app.localhost:8443` returns `403`, read the response body. oidcld now includes the observed peer IP plus raw `Forwarded` and `X-Forwarded-*` header values so you can see whether the request carried proxy metadata at all.
- `postgres` is intentionally unused in this version of the sample.
