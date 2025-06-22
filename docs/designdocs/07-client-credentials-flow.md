# Design Document 07: OAuth 2.0 Client Credentials Flow

**Document ID:** DD-07  
**Title:** OAuth 2.0 Client Credentials Flow Implementation  
**Date:** 2025-06-23  
**Author:** Development Team  
**Status:** Implemented  
**Version:** 2.0  

---

## 1. Executive Summary

### 1.1 Overview
This document outlines the implemented OAuth 2.0 Client Credentials Flow (RFC 6749 Section 4.4) in the OpenID Connect Test Identity Provider. The implementation is built on the zitadel/oidc library and provides standards-compliant machine-to-machine authentication for testing and development scenarios.

### 1.2 Objectives
- ✅ Implement standards-compliant OAuth 2.0 Client Credentials Flow
- ✅ Enable service-to-service authentication testing
- ✅ Maintain zero-configuration approach for development ease
- ✅ Ensure integration with zitadel/oidc library
- ✅ Support custom scopes and JWT claims

### 1.3 Scope
- ✅ `/token` endpoint support for `grant_type=client_credentials`
- ✅ Client authentication mechanisms
- ✅ JWT token generation with custom claims
- ✅ Discovery endpoint integration
- ✅ Comprehensive error handling
- ✅ Scope-based access control

---

## 2. Architecture Overview

### 2.1 Implementation Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Client Credentials Flow                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client Application                                         │
│       │                                                     │
│       │ POST /token                                         │
│       │ grant_type=client_credentials                       │
│       │ client_id=service-client                            │
│       │ client_secret=secret                                │
│       │ scope=read write                                    │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Zitadel OIDC Provider                      │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │            Token Endpoint Handler                   │ │ │
│  │  │                                                     │ │ │
│  │  │  1. Validate grant_type                             │ │ │
│  │  │  2. Authenticate client                             │ │ │
│  │  │  3. Validate scopes                                 │ │ │
│  │  │  4. Generate access token                           │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│       │                                                     │
│       │ HTTP 200 OK                                         │
│       │ {                                                   │
│       │   "access_token": "eyJ...",                         │
│       │   "token_type": "Bearer",                           │
│       │   "expires_in": 3600,                               │
│       │   "scope": "read write"                             │
│       │ }                                                   │
│       ▼                                                     │
│  Client Application                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Storage Adapter Integration

The implementation uses a custom `StorageAdapter` that implements the zitadel/oidc interfaces:

```go
// ClientCredentials implements op.Client interface
func (s *StorageAdapter) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error)

// ClientCredentialsTokenRequest implements op.TokenRequest interface  
func (s *StorageAdapter) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error)
```

---

## 3. Implementation Details

### 3.1 Client Authentication

#### 3.1.1 Authentication Methods
The implementation supports standard OAuth 2.0 client authentication:

**Form-based Authentication:**
```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=read+write
```

**HTTP Basic Authentication:**
```http
POST /token HTTP/1.1
Authorization: Basic c2VydmljZS1jbGllbnQ6c2VjcmV0
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read+write
```

#### 3.1.2 Client Validation
```go
func validateClientCredentials(clientID, clientSecret string) error {
    if clientID == "" {
        return ErrMissingClientCredentials
    }
    if clientSecret == "" {
        return ErrMissingClientCredentials
    }
    return nil
}
```

### 3.2 Scope Management

#### 3.2.1 Global Scopes
Configured in `oidcld.yaml`:
```yaml
oidcld:
  valid_scopes:
    - "read"
    - "write"
    - "admin"
```

#### 3.2.2 Client-Specific Scopes
Clients can be configured with specific scope restrictions:
```yaml
# Future enhancement - currently all clients have access to all valid scopes
```

#### 3.2.3 Scope Validation Logic
```go
func (c *ClientCredentialsClient) ValidateScope(scopes []string) error {
    for _, scope := range scopes {
        if !slices.Contains(c.validScopes, scope) {
            return fmt.Errorf("invalid scope: %s", scope)
        }
    }
    return nil
}
```

### 3.3 Token Generation

#### 3.3.1 JWT Structure
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id"
  },
  "payload": {
    "iss": "https://localhost:18888",
    "sub": "service-client",
    "aud": ["service-client"],
    "exp": 1640995200,
    "iat": 1640991600,
    "scope": "read write",
    "client_id": "service-client",
    "token_type": "Bearer"
  }
}
```

#### 3.3.2 Token Response
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### 3.4 Error Handling

#### 3.4.1 Standard Error Responses
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

#### 3.4.2 Error Types
- `invalid_request`: Missing or malformed parameters
- `invalid_client`: Client authentication failed
- `invalid_grant`: Unsupported grant type
- `invalid_scope`: Requested scope is invalid
- `server_error`: Internal server error

---

## 4. Configuration

### 4.1 YAML Configuration
```yaml
# OpenID Connect IdP settings
oidcld:
  valid_audiences:
    - "service-client"
    - "api-client"
  valid_scopes:
    - "read"
    - "write"
    - "admin"
  expired_in: 3600  # Token expiration in seconds

# Users section not used for client credentials
users: {}
```

### 4.2 Discovery Endpoint Updates
The discovery endpoint includes client credentials support:
```json
{
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ]
}
```

---

## 5. Usage Examples

### 5.1 cURL Example
```bash
# Using form-based authentication
curl -X POST http://localhost:18888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=read+write"

# Using HTTP Basic authentication
curl -X POST http://localhost:18888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'service-client:secret' | base64)" \
  -d "grant_type=client_credentials&scope=read+write"
```

### 5.2 Go Client Example
```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strings"
)

type TokenResponse struct {
    AccessToken string `json:"access_token"`
    TokenType   string `json:"token_type"`
    ExpiresIn   int    `json:"expires_in"`
    Scope       string `json:"scope"`
}

func getClientCredentialsToken() (*TokenResponse, error) {
    tokenURL := "http://localhost:18888/token"
    
    data := url.Values{}
    data.Set("grant_type", "client_credentials")
    data.Set("client_id", "service-client")
    data.Set("client_secret", "secret")
    data.Set("scope", "read write")
    
    req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, err
    }
    
    return &tokenResp, nil
}
```

### 5.3 JavaScript/Node.js Example
```javascript
const axios = require('axios');

async function getClientCredentialsToken() {
    const tokenUrl = 'http://localhost:18888/token';
    
    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    params.append('client_id', 'service-client');
    params.append('client_secret', 'secret');
    params.append('scope', 'read write');
    
    try {
        const response = await axios.post(tokenUrl, params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        
        return response.data;
    } catch (error) {
        console.error('Token request failed:', error.response.data);
        throw error;
    }
}
```

---

## 6. Testing

### 6.1 Unit Tests
The implementation includes comprehensive unit tests:

```go
func TestStorageAdapter_ClientCredentials(t *testing.T) {
    // Test client credentials validation
}

func TestStorageAdapter_ClientCredentialsTokenRequest(t *testing.T) {
    // Test token request creation
}

func TestClientCredentialsClient_ValidateScope(t *testing.T) {
    // Test scope validation
}
```

### 6.2 Integration Tests
```go
func TestOIDCServerClientCredentialsFlow(t *testing.T) {
    // End-to-end client credentials flow test
}
```

### 6.3 Manual Testing
```bash
# Start the server
./oidcld serve

# Test client credentials flow
curl -X POST http://localhost:18888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test-client&client_secret=test-secret&scope=read+write"
```

---

## 7. Security Considerations

### 7.1 Client Secret Management
- **Development**: Simple string-based secrets
- **Testing**: Configurable client credentials
- **Production**: Not recommended (use proper IdP)

### 7.2 Token Security
- **Signing**: RSA-256 signatures
- **Expiration**: Configurable token lifetime
- **Scope**: Principle of least privilege
- **Audience**: Proper audience validation

### 7.3 Transport Security
- **HTTPS**: Recommended for production-like testing
- **TLS**: mkcert integration for trusted certificates

---

## 8. Performance Considerations

### 8.1 Token Generation
- **Speed**: Fast in-memory operations
- **Caching**: No caching required (stateless)
- **Scalability**: Single-threaded design suitable for testing

### 8.2 Storage
- **Memory**: Minimal client data storage
- **Persistence**: No persistence required
- **Cleanup**: Automatic token expiration

---

## 9. Limitations and Future Enhancements

### 9.1 Current Limitations
- **Client Registration**: Static configuration only
- **Client Scopes**: Global scope model
- **Rate Limiting**: Not implemented
- **Audit Logging**: Basic logging only

### 9.2 Future Enhancements
- **Dynamic Client Registration**: Runtime client management
- **Client-Specific Scopes**: Per-client scope restrictions
- **Advanced Authentication**: Certificate-based authentication
- **Monitoring**: Enhanced metrics and logging

---

## 10. Migration Notes

### 10.1 From Custom Implementation
The client credentials flow has been migrated from a custom implementation to use the zitadel/oidc library:

**Benefits Achieved:**
- ✅ Standards compliance (RFC 6749)
- ✅ Better error handling
- ✅ Improved security
- ✅ Reduced maintenance burden
- ✅ Integration with certified OIDC ecosystem

**Breaking Changes:**
- None - backward compatibility maintained

### 10.2 Configuration Migration
Existing configurations continue to work without changes:
```yaml
# No changes required to existing oidcld.yaml files
oidcld:
  valid_scopes:
    - "read"
    - "write"
```

---

## 11. Conclusion

The OAuth 2.0 Client Credentials Flow implementation provides a robust, standards-compliant solution for machine-to-machine authentication testing. Built on the mature zitadel/oidc library, it offers enterprise-grade security while maintaining the simplicity required for development and testing environments.

The implementation successfully balances standards compliance with ease of use, making it an ideal choice for testing scenarios that require service-to-service authentication without the complexity of production identity providers.
