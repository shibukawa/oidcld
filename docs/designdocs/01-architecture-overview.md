# Architecture Overview

## Document Information
- **Document Type**: Architecture Design Document
- **Version**: 2.0
- **Date**: 2025-06-23
- **Author**: OpenIDLD Team
- **Status**: Implemented

## Executive Summary

OpenIDLD is a fake OpenID Connect Identity Provider designed specifically for testing and development environments. It provides a fully functional OpenID Connect server using the mature zitadel/oidc library, ensuring standards compliance and real-world compatibility.

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OpenIDLD System                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │    CLI      │  │    HTTP     │  │        MCP          │  │
│  │  Interface  │  │   Server    │  │      Server         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │           Zitadel OIDC Provider (v3)                   │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │    Auth     │ │   Token     │ │   Discovery     │   │  │
│  │  │  Endpoint   │ │  Endpoint   │ │   Endpoint      │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │    JWKS     │ │   UserInfo  │ │   End Session   │   │  │
│  │  │  Endpoint   │ │  Endpoint   │ │   Endpoint      │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  └─────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Custom Storage Adapter                     │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │    Auth     │ │   Token     │ │      User       │   │  │
│  │  │   Storage   │ │   Storage   │ │    Storage      │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  └─────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                Configuration Layer                      │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │    YAML     │ │     JWT     │ │     EntraID     │   │  │
│  │  │   Config    │ │    Keys     │ │  Compatibility  │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

#### 1. Zitadel OIDC Provider
- **Library**: `github.com/zitadel/oidc/v3`
- **Purpose**: Standards-compliant OpenID Connect implementation
- **Benefits**: 
  - Full OpenID Connect Core 1.0 compliance
  - OAuth 2.0 Authorization Framework support
  - Battle-tested security implementations
  - Regular updates and maintenance

#### 2. Storage Adapter
- **File**: `internal/server/storage_adapter.go`
- **Purpose**: Implements zitadel/oidc storage interfaces
- **Features**:
  - In-memory storage for testing
  - User management
  - Token lifecycle management
  - Session management

#### 3. Configuration Management
- **File**: `internal/config/config.go`
- **Format**: YAML-based configuration
- **Features**:
  - User definitions
  - Scope management
  - EntraID compatibility settings
  - Runtime configuration reloading

#### 4. JWT Management
- **Directory**: `internal/server/jwt/`
- **Components**:
  - Key management (`keys.go`)
  - Algorithm support (`algorithms.go`)
  - Token validation (`validation.go`)
  - JWT manager (`manager.go`)

## Supported Features

### OpenID Connect Flows
- ✅ Authorization Code Flow
- ✅ Client Credentials Flow  
- ✅ Device Flow
- ✅ Refresh Token Flow
- ✅ End Session (Logout)

### Response Modes
- ✅ Query mode (`response_mode=query`)
- ✅ Fragment mode (`response_mode=fragment`)
- ⚠️ Form Post mode (falls back to query)

### Standards Compliance
- ✅ OpenID Connect Core 1.0
- ✅ OpenID Connect Discovery 1.0
- ✅ OAuth 2.0 Authorization Framework
- ✅ JSON Web Token (JWT) Profile
- ✅ JSON Web Key Set (JWKS)
- ✅ PKCE (Proof Key for Code Exchange)

### Enterprise Features
- ✅ EntraID/AzureAD compatibility
- ✅ Microsoft ecosystem integration
- ✅ Custom JWT claims
- ✅ Scope-based access control

## Deployment Architecture

### Single Binary Deployment
```
┌─────────────────────────────────────┐
│            Host System              │
│  ┌─────────────────────────────────┐ │
│  │         oidcld binary           │ │
│  │  ┌─────────────────────────────┐ │ │
│  │  │      HTTP Server            │ │ │
│  │  │    (Port 18888)             │ │ │
│  │  └─────────────────────────────┘ │ │
│  │  ┌─────────────────────────────┐ │ │
│  │  │    Configuration            │ │ │
│  │  │   (oidcld.yaml)             │ │ │
│  │  └─────────────────────────────┘ │ │
│  │  ┌─────────────────────────────┐ │ │
│  │  │      JWT Keys               │ │ │
│  │  │  (.oidcld.key/.pub.key)     │ │ │
│  │  └─────────────────────────────┘ │ │
│  └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### Docker Deployment
```
┌─────────────────────────────────────┐
│         Docker Container            │
│  ┌─────────────────────────────────┐ │
│  │         oidcld binary           │ │
│  │       (Multi-arch support)     │ │
│  │    linux/amd64, linux/arm64    │ │
│  └─────────────────────────────────┘ │
│  ┌─────────────────────────────────┐ │
│  │        Volume Mounts            │ │
│  │   /app/config.yaml (optional)   │ │
│  │   /app/certs/ (for HTTPS)       │ │
│  └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

## Security Architecture

### Key Management
- RSA 2048-bit keys (default)
- ECDSA support (ES256, ES384, ES512)
- Automatic key generation
- External key file support

### Token Security
- JWT with RS256 signing (default)
- Configurable token expiration
- Refresh token rotation
- Secure token storage

### Transport Security
- HTTPS support with mkcert integration
- TLS certificate management
- Secure redirect URI validation

## Integration Points

### Client Integration
- Standard OpenID Connect clients
- Microsoft MSAL libraries
- Certified OIDC client libraries
- Custom HTTP clients

### Development Tools
- MCP (Model Context Protocol) server
- CLI configuration management
- Docker integration
- CI/CD pipeline support

## Performance Characteristics

### Scalability
- Single-threaded design (suitable for testing)
- In-memory storage (fast, ephemeral)
- Minimal resource requirements
- Stateless operation (except for sessions)

### Reliability
- Graceful error handling
- Configuration validation
- Health check endpoint
- Structured logging

## Migration Notes

This architecture represents the current implementation after migrating from a custom OpenID Connect implementation to the mature zitadel/oidc library. Key benefits achieved:

1. **Standards Compliance**: Full OpenID Connect and OAuth 2.0 compliance
2. **Enterprise Compatibility**: EntraID/AzureAD support
3. **Reduced Maintenance**: Leveraging battle-tested library
4. **Enhanced Security**: Professional-grade security implementations
5. **Better Testing**: Certified client library compatibility
