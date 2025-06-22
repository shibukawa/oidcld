# OpenID Connect Implementation Design

## Document Information
- **Document Type**: Feature Design Document
- **Version**: 2.0
- **Date**: 2025-06-23
- **Author**: OpenIDLD Team
- **Status**: Implemented

## Overview

This document describes the OpenID Connect (OIDC) implementation in OpenIDLD, which is built on the mature zitadel/oidc library. The implementation provides full protocol compliance, enterprise compatibility, and testing-specific features.

## OpenID Connect Protocol Support

### Supported Flows

#### 1. Authorization Code Flow
- **Standard**: OpenID Connect Core 1.0
- **Use Case**: Web applications, mobile apps with secure backend
- **Security**: PKCE support for enhanced security
- **Implementation**: Full flow with authorization code exchange

```
Client → /authorize (authorization request)
       ← User selection/authentication
       ← Redirect with authorization code
Client → /token (code exchange)
       ← Access token + ID token + Refresh token (optional)
```

**Key Features:**
- Response mode support (query, fragment)
- State parameter validation
- Nonce parameter support
- Custom scope handling
- EntraID/AzureAD compatibility

#### 2. Client Credentials Flow
- **Standard**: OAuth 2.0 RFC 6749
- **Use Case**: Service-to-service authentication
- **Security**: Client authentication required
- **Implementation**: Direct token issuance

```
Client → /token (client credentials)
       ← Access token
```

**Key Features:**
- Client ID/secret validation
- Scope-based access control
- Custom JWT claims
- Token expiration management

#### 3. Device Flow
- **Standard**: OAuth 2.0 Device Authorization Grant
- **Use Case**: IoT devices, CLI applications
- **Security**: User code verification
- **Implementation**: Polling-based token retrieval

```
Client → /device (device authorization)
       ← Device code + User code + Verification URI
User   → Verification URI (user authentication)
Client → /token (polling with device code)
       ← Access token + ID token
```

#### 4. Refresh Token Flow
- **Standard**: OAuth 2.0 RFC 6749
- **Use Case**: Long-lived sessions
- **Security**: Refresh token rotation
- **Implementation**: Token renewal

```
Client → /token (refresh token grant)
       ← New access token + New refresh token
```

### Response Modes

#### Query Mode (Default)
- **Parameter**: `response_mode=query`
- **Usage**: Traditional web applications
- **Format**: `https://client.example.com/callback?code=ABC&state=XYZ`

#### Fragment Mode
- **Parameter**: `response_mode=fragment`
- **Usage**: Single Page Applications (SPA), MSAL.js
- **Format**: `https://client.example.com/callback#code=ABC&state=XYZ`
- **Compatibility**: Required for EntraID/AzureAD clients

#### Form Post Mode
- **Parameter**: `response_mode=form_post`
- **Status**: Falls back to query mode
- **Note**: Future enhancement planned

## Endpoint Implementation

### Discovery Endpoint
- **Path**: `/.well-known/openid-configuration`
- **Standard**: OpenID Connect Discovery 1.0
- **Purpose**: Automatic client configuration

**Response includes:**
```json
{
  "issuer": "https://localhost:18888",
  "authorization_endpoint": "https://localhost:18888/authorize",
  "token_endpoint": "https://localhost:18888/token",
  "userinfo_endpoint": "https://localhost:18888/userinfo",
  "jwks_uri": "https://localhost:18888/keys",
  "end_session_endpoint": "https://localhost:18888/end_session",
  "device_authorization_endpoint": "https://localhost:18888/device",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

### Authorization Endpoint
- **Path**: `/authorize`
- **Method**: GET
- **Purpose**: Initiate authorization flow

**Parameters:**
- `response_type`: "code" (required)
- `client_id`: Client identifier (required)
- `redirect_uri`: Callback URL (required)
- `scope`: Requested scopes (required)
- `state`: CSRF protection (recommended)
- `nonce`: Replay protection (optional)
- `response_mode`: Response delivery mode (optional)
- `code_challenge`: PKCE challenge (optional)
- `code_challenge_method`: PKCE method (optional)

### Token Endpoint
- **Path**: `/token`
- **Method**: POST
- **Purpose**: Exchange codes for tokens

**Grant Types:**
1. **authorization_code**: Exchange authorization code
2. **client_credentials**: Direct client authentication
3. **refresh_token**: Refresh access tokens
4. **urn:ietf:params:oauth:grant-type:device_code**: Device flow completion

### UserInfo Endpoint
- **Path**: `/userinfo`
- **Method**: GET
- **Purpose**: Retrieve user information
- **Authentication**: Bearer token required

### JWKS Endpoint
- **Path**: `/keys`
- **Method**: GET
- **Purpose**: Public key distribution
- **Format**: JSON Web Key Set

### End Session Endpoint
- **Path**: `/end_session`
- **Methods**: GET, POST
- **Purpose**: Logout functionality
- **Parameters**:
  - `id_token_hint`: ID token for session identification
  - `post_logout_redirect_uri`: Redirect after logout
  - `state`: State preservation

### Device Authorization Endpoint
- **Path**: `/device`
- **Method**: POST
- **Purpose**: Initiate device flow
- **Response**: Device code, user code, verification URI

## JWT Implementation

### Token Structure
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id"
  },
  "payload": {
    "iss": "https://localhost:18888",
    "sub": "user-id",
    "aud": "client-id",
    "exp": 1640995200,
    "iat": 1640991600,
    "auth_time": 1640991600,
    "nonce": "random-nonce",
    "email": "user@example.com",
    "name": "User Name",
    "custom_claim": "custom_value"
  }
}
```

### Supported Algorithms
- **RS256**: RSA with SHA-256 (default)
- **ES256**: ECDSA with SHA-256
- **ES384**: ECDSA with SHA-384
- **ES512**: ECDSA with SHA-512

### Key Management
- Automatic key generation
- External key file support
- Key rotation capability
- JWKS publication

## EntraID/AzureAD Compatibility

### Compatibility Features
- Fragment response mode support
- Microsoft-specific JWT claims
- Tenant ID configuration
- Version-specific endpoints (v1/v2)

### Configuration Example
```yaml
entraid:
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  version: "v2"
```

### MSAL.js Integration
```javascript
const msalConfig = {
  auth: {
    clientId: 'your-client-id',
    authority: 'https://localhost:18888',
    redirectUri: 'https://localhost:3000/callback'
  }
};
```

## User Management

### User Configuration
```yaml
users:
  testuser:
    display_name: "Test User"
    extra_valid_scopes:
      - "admin"
      - "read"
    extra_claims:
      email: "test@example.com"
      role: "admin"
      department: "engineering"
```

### Scope Validation
- Global scopes: Available to all users
- User-specific scopes: Defined per user
- Standard scopes: `openid`, `profile`, `email`, `offline_access`
- Custom scopes: Configurable per deployment

## Security Features

### PKCE Support
- **Method**: S256 (SHA256)
- **Purpose**: Enhanced security for public clients
- **Configuration**: Optional/required per client

### State Parameter
- **Purpose**: CSRF protection
- **Validation**: Automatic state verification
- **Encoding**: Proper URL encoding handling

### Nonce Parameter
- **Purpose**: Replay attack prevention
- **Validation**: ID token nonce verification
- **Configuration**: Optional/required

### Token Security
- **Signing**: RSA/ECDSA signatures
- **Expiration**: Configurable token lifetime
- **Refresh**: Secure token renewal
- **Revocation**: Token invalidation support

## Error Handling

### Standard Error Responses
```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: client_id",
  "error_uri": "https://tools.ietf.org/html/rfc6749#section-4.1.2.1"
}
```

### Error Types
- `invalid_request`: Malformed request
- `unauthorized_client`: Client authentication failed
- `access_denied`: User denied authorization
- `unsupported_response_type`: Unsupported response type
- `invalid_scope`: Invalid scope requested
- `server_error`: Internal server error
- `temporarily_unavailable`: Service temporarily unavailable

## Testing Features

### User Selection Interface
- Simple HTML interface for user selection
- No real authentication required
- Configurable user list
- Direct user specification via URL parameters

### Health Check
- **Endpoint**: `/health`
- **Purpose**: Service monitoring
- **Response**: JSON status information

### Configuration Reloading
- **Feature**: Runtime configuration updates
- **Trigger**: File system watch
- **Scope**: User definitions, scopes, token settings
- **Limitations**: Core settings require restart

## Performance Considerations

### In-Memory Storage
- **Benefit**: Fast access, no database required
- **Limitation**: Data lost on restart
- **Use Case**: Perfect for testing environments

### Stateless Design
- **Benefit**: Horizontal scaling potential
- **Exception**: Session storage for user flows
- **Cleanup**: Automatic token expiration

### Resource Usage
- **Memory**: Minimal footprint
- **CPU**: Low computational requirements
- **Network**: Standard HTTP/HTTPS

## Integration Examples

### Standard OIDC Client
```javascript
const config = {
  authority: 'https://localhost:18888',
  client_id: 'test-client',
  redirect_uri: 'https://localhost:3000/callback',
  response_type: 'code',
  scope: 'openid profile email'
};
```

### Client Credentials
```bash
curl -X POST https://localhost:18888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=read write"
```

### Device Flow
```bash
# Step 1: Initiate device flow
curl -X POST https://localhost:18888/device \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=device-client&scope=openid profile"

# Step 2: Poll for token
curl -X POST https://localhost:18888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEVICE_CODE&client_id=device-client"
```

## Migration Notes

This implementation represents a complete migration from custom OpenID Connect code to the mature zitadel/oidc library. Key improvements:

1. **Standards Compliance**: Full OpenID Connect Core 1.0 compliance
2. **Enterprise Ready**: EntraID/AzureAD compatibility out of the box
3. **Security**: Battle-tested security implementations
4. **Maintenance**: Reduced maintenance burden through library usage
5. **Compatibility**: Works with certified OIDC client libraries

The migration maintains backward compatibility for existing configurations while adding new enterprise features and improved standards compliance.
