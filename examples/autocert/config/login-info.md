# Compose Sample Environment

This login page belongs to the Docker Compose sample in this repository.

## Quick Links

- [Sample Setup README](../README.md)
- [OpenID Configuration](https://oidc.localhost:8443/.well-known/openid-configuration)
- [HTTP Metadata Endpoint](http://localhost:18888/.well-known/openid-configuration)
- [myencrypt CA Download](http://localhost:14000/download)
- [React Sample App](http://app.localhost:3000/)

## Notes

- This environment is for local development only.
- HTTPS traffic is served at `https://oidc.localhost:8443`.
- The HTTP listener on `http://localhost:18888` is metadata-only.
- Import the development CA from myencrypt before testing browser flows.
