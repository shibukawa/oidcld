# Design Documents Index

This directory contains design documents for the OpenID Connect Test Identity Provider project.

## Document List

| ID | Title | Date | Status | Version |
|----|-------|------|--------|---------|
| [DD-01](./01-architecture-overview.md) | Architecture Overview | 2025-06-20 | Implemented | 2.0 |
| [DD-02](./02-openid-connect-implementation.md) | OpenID Connect Implementation | 2025-06-20 | Implemented | 2.0 |
| [DD-03](./03-mcp-server-design.md) | MCP Server Design | 2025-06-20 | Implemented | 1.0 |
| [DD-05](./05-configuration-management.md) | Configuration Management | 2025-06-20 | Implemented | 1.0 |
| [DD-07](./07-client-credentials-flow.md) | OAuth 2.0 Client Credentials Flow | 2025-06-22 | Implemented | 1.0 |
| [DD-10](./10-use-mature-oidc-implementation.md) | Use Mature OIDC Implementation | 2025-06-22 | Implemented | 1.0 |

## Document Status Legend

- **Draft**: Document is being written or reviewed
- **Approved**: Document has been approved for implementation
- **Implemented**: Feature has been implemented according to the design
- **Archived**: Document is no longer relevant or has been superseded

## Removed Documents

The following documents have been removed as the features are no longer part of the current implementation:

- **DD-04**: Pre-specified User Authentication - Removed (feature not implemented in zitadel/oidc migration)
- **DD-09**: Client Credential Flow Example - Removed (superseded by DD-07)

## Design Document Template

When creating new design documents, follow this naming convention:
- `DD-XX-feature-name.md` where XX is a two-digit number
- Include document information header with version, date, and status
- Follow the standard template structure for consistency

## Current Architecture

The current implementation is based on the mature zitadel/oidc library, providing:
- Full OpenID Connect Core 1.0 compliance
- OAuth 2.0 Authorization Framework support
- EntraID/AzureAD compatibility
- Multiple response modes (query, fragment)
- Client Credentials Flow
- Device Flow
- Refresh Token support
- End Session (logout) support
