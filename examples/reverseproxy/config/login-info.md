# Compose Sample Environment

This login page belongs to the Docker Compose sample in this repository.

## Quick Links

- [Sample Setup README](../README.md)
- [OpenID Configuration](https://oidc.localhost:8443/.well-known/openid-configuration)
- [HTTP Metadata Endpoint](http://localhost:8888/.well-known/openid-configuration)
- [Developer Console](http://localhost:8888/console/)
- [Root CA Download](http://localhost:8888/console/api/downloads/root-ca.pem)
- [React Sample App](https://app.localhost:8443/)

## Notes

- This environment is for local development only.
- HTTPS traffic is served at `https://oidc.localhost:8443` and `https://app.localhost:8443`.
- The HTTP listener on `http://localhost:8888` serves the Developer Console and metadata endpoints.
- Import the development root CA from OIDCLD before testing browser flows.
