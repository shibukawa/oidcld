# OpenID Connect for Local Development: OpenID Connect Test Identity Provider

![console](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/console.png)

## Terminology

This project uses terminology from xUnit test patterns to clearly describe its purpose and functionality:

### **Fake vs Mock**
- **Fake**: A working implementation with simplified behavior, suitable for testing. Fakes have real business logic but take shortcuts (e.g., in-memory storage instead of a database).
- **Mock**: An object that verifies behavior by recording interactions and asserting expectations.

### **This Project is a "Fake"**
This OpenID Connect Identity Provider is a **fake** implementation because it:
- Provides a fully functional OpenID Connect server with real protocol compliance
- Uses simplified implementations (in-memory storage, test certificates, user selection UI)
- Enables actual authentication flows for testing purposes
- Does not verify specific interactions or assert expectations like a mock would

The term "fake" accurately describes this tool's role in testing scenarios - it's a real, working identity provider designed specifically for development and testing environments.

## Service Purpose

### Overview
A fake OpenID Connect Identity Provider (IdP) designed for testing and development purposes. Built on the mature **zitadel/oidc library**, this service provides enterprise-grade OpenID Connect compliance while maintaining the simplicity needed for development and testing.

### Primary Function
- Provides standards-compliant OpenID Connect authentication flows for testing
- Enables easy user selection for login without real credentials
- Supports local and test environment development workflows
- Facilitates E2E testing of applications that require OpenID Connect authentication
- Compatible with Microsoft EntraID/AzureAD clients and MSAL libraries

----

![screenshot](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/login-screen.png)

**Login Screen:** No password, just click to login. It helps you to test. No special no-login-local-dev-only-logic anymore.

----

### Core Features
- **Standards-Compliant Implementation**: Built on zitadel/oidc v3 library for full OpenID Connect Core 1.0 compliance
- **Multiple OAuth 2.0/OpenID Connect Flows**: Authorization Code Flow, Client Credentials Flow, Device Flow, and Refresh Token Flow
- **Response Mode Support**: Query mode and Fragment mode (required for EntraID/AzureAD compatibility)
- **PKCE Support**: Proof Key for Code Exchange implementation for enhanced security
- **Refresh Token Support**: Optional refresh token generation and validation for long-lived sessions
- **End Session Support**: OpenID Connect RP-Initiated Logout with configurable discovery visibility
- **HTTPS Support**: Native HTTPS server with mkcert integration for trusted local certificates
- **OpenID Discovery**: Standards-compliant `/.well-known/openid-configuration` endpoint
- **Custom JWT Claims**: YAML configuration supports additional information in JWT tokens
- **EntraID/AzureAD Compatibility**: Full Microsoft ecosystem integration with fragment mode support
- **MCP Server Mode**: Model Context Protocol server for configuration management and automation
- **Simple User Management**: Users defined via YAML configuration file with scope-based access control
- **Enterprise Ready**: Production-grade security with battle-tested cryptographic implementations

## Deployment

### Environment Requirements
- Single binary (written in Go 1.24)
- No database required (in-memory storage)
- YAML configuration file for user definitions

### Setup Instructions

#### Installation Options

**Option 1: Go Get Tool (Go 1.24+)**
```bash
go get -tool github.com/shibukawa/oidcld@latest
```

**Option 2: Download from GitHub Releases**
1. Visit the [GitHub releases page](https://github.com/shibukawa/oidcld/releases)
2. Download the appropriate binary for your operating system
3. Make the binary executable (on Unix-like systems): `chmod +x oidcld`

**Option 3: Docker**
```bash
docker pull ghcr.io/shibukawa/oidcld
```

#### Configuration and Startup
1. Generate initial configuration with keys: `./oidcld init`
   - Interactive setup with options for standard OpenID, EntraID v1, or EntraID v2
   - HTTPS configuration with mkcert certificate generation
   - Generates cryptographic key files (`.oidcld.key`, `.oidcld.pub.key`)
   - Creates YAML configuration file (`oidcld.yaml`)
2. Configure users in the generated YAML configuration file
3. Start the service: `./oidcld` or `./oidcld --config your-config.yaml`
4. For HTTPS: `./oidcld --https` (uses localhost.pem/localhost-key.pem by default)

### Configuration
- **Port**: 18888 (default)
  - Command line: `--port 8080`
  - Environment variable: `PORT=8080`
- **Configuration File**: oidcld.yaml (default)
  - Command line: `--config config.yaml`
- **Cryptographic Keys**: External key files for security
  - Private key: `.oidcld.key` (default, if there is not exists, it generates key on the fly)
  - Public key: `.oidcld.pub.key` (default, if there is not exists, it generates key on the fly)
- **User Configuration**: Define users in YAML config file

#### YAML Configuration Sample
```yaml
# OpenID Connect IdP settings
oidcld:
  # iss: "http://localhost:18888"
  pkce_required: false
  nonce_required: false
  expired_in: 3600  # Token expiration in seconds
  # algorithm: "RS256"  # Optional, defaults to RS256
  # Standard scopes (openid, profile, email) are always included
  valid_scopes:  # Optional custom scopes
    - "admin"
    - "read"
    - "write"
  # private_key_path: ".oidcld.key"      # Optional, generates at runtime if empty
  # public_key_path: ".oidcld.pub.key"   # Optional, generates at runtime if empty
  refresh_token_enabled: true             # Enable refresh token support
  refresh_token_expiry: 86400             # Refresh token expiry in seconds (24 hours)
  end_session_enabled: true               # Enable logout/end session functionality
  end_session_endpoint_visible: true      # Show end_session_endpoint in discovery (optional)

# EntraID/AzureAD compatibility settings
entraid:
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  version: "v2"

# CORS (Cross-Origin Resource Sharing) settings for SPA development
cors:
  enabled: true                           # Enable CORS support
  allowed_origins:                        # List of allowed origins
    - "http://localhost:3000"             # React/Vue dev server
    - "http://localhost:5173"             # Vite dev server
    - "https://localhost:3000"            # HTTPS dev server
  allowed_methods:                        # Allowed HTTP methods
    - "GET"
    - "POST"
    - "OPTIONS"
  allowed_headers:                        # Allowed request headers
    - "Content-Type"
    - "Authorization"
    - "Accept"

# User definitions
users:
  user1:
    display_name: "John Doe"
    extra_valid_scopes:
      - "admin"
      - "read"
      - "write"
    extra_claims:
      email: "john.doe@example.com"
      role: "admin"
      department: "engineering"
  user2:
    display_name: "Jane Smith"
    extra_valid_scopes:
      - "read"
    extra_claims:
      email: "jane.smith@example.com"
      role: "user"
      department: "marketing"
  testuser:
    display_name: "Test User"
    extra_claims:
      email: "test@example.com"
      groups: ["testers", "developers"]
```

### Running the Service
```bash
./oidcld                           # Start OpenID Connect server (default config: oidcld.yaml)
./oidcld --config config.yaml     # Start with custom config file
./oidcld --watch                   # Start with automatic config reload on file changes
./oidcld -w --config config.yaml  # Start with custom config and watch mode
./oidcld --https                   # Start with HTTPS (uses localhost.pem/localhost-key.pem)
./oidcld --https --cert-file cert.pem --key-file key.pem  # Start with custom certificates
./oidcld mcp                       # Start as MCP server (stdin/stdout mode)
./oidcld mcp --port 3001          # Start as MCP HTTP server
```

#### HTTPS Setup with mkcert

For production-like HTTPS testing with trusted certificates:

```bash
# Install mkcert (macOS)
brew install mkcert

# Install mkcert (Linux/Windows)
# See: https://github.com/FiloSottile/mkcert#installation

# Initialize with HTTPS and mkcert
./oidcld init --https --mkcert

# EntraID templates with mkcert (HTTPS is automatic for EntraID)
./oidcld init --template entraid-v2 --mkcert

# Or use the interactive wizard
./oidcld init
# Select: Standard OpenID Connect or EntraID template
# For Standard: Enable HTTPS: y
# For EntraID: HTTPS is automatically enabled
# Generate mkcert certificates: y

# Start HTTPS server
./oidcld --https
```

#### Watch Mode

The `--watch` (`-w`) option enables automatic configuration reloading when the config file changes:

```bash
./oidcld --watch
# or
./oidcld -w
```

**Features:**
- **Automatic Reload**: Configuration is reloaded automatically when the file is modified
- **Debounced Updates**: Multiple rapid changes are debounced to avoid excessive reloads
- **Validation**: Invalid configurations are rejected, keeping the previous valid config
- **Runtime Safety**: Critical settings like issuer URL and signing algorithm cannot be changed at runtime
- **Colored Output**: Clear, colorful feedback about reload success/failure with configuration details
- **Detailed Logging**: Visual indicators and emojis for better readability

**What can be changed at runtime:**
- User definitions and claims
- Valid audiences and scopes
- Token expiration settings
- PKCE and nonce requirements
- Refresh token settings

**What requires a restart:**
- Issuer URL
- Signing algorithm
- Port number
- Certificate/key files

**Example workflow:**
1. Start server with watch mode: `./oidcld --watch`
2. Edit `oidcld.yaml` to add new users or modify settings
3. Save the file - configuration reloads automatically
4. Check logs for reload confirmation and any validation errors

**Colored Output Examples:**
- 🚀 Server startup messages in green
- 🔄 Configuration reload messages in cyan
- ✅ Success messages in green
- ❌ Error messages in red
- 🌐 HTTP request logs with color-coded status codes

### Refresh Token Support

When refresh tokens are enabled, the token endpoint will return both access tokens and refresh tokens:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def50200e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Using Refresh Tokens

To refresh an access token, make a POST request to the token endpoint:

```bash
curl -X POST http://localhost:18888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=def50200e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

#### Configuration Options

```yaml
oidcld:
  refresh_token_enabled: true    # Enable/disable refresh token generation
  refresh_token_expiry: 86400    # Refresh token expiry in seconds (default: 24 hours)
  expired_in: 3600               # Access token expiry in seconds (default: 1 hour)
```

### Logout / End Session Support

The OpenID Connect test identity provider supports logout functionality through the end session endpoint, following the OpenID Connect RP-Initiated Logout specification.

#### Configuration

```yaml
oidcld:
  end_session_enabled: true               # Enable logout/end session functionality
  end_session_endpoint_visible: true      # Show end_session_endpoint in discovery (optional)
```

**Configuration Options:**
- `end_session_enabled`: Controls whether the logout functionality is available
- `end_session_endpoint_visible`: Controls whether the `end_session_endpoint` appears in the `.well-known/openid-configuration` discovery document

**Note:** The logout functionality is available even when `end_session_endpoint_visible` is set to `false`. This allows for private logout endpoints that are not advertised in the discovery document.

#### Discovery Endpoint

When `end_session_endpoint_visible` is `true`, the discovery endpoint will include:

```json
{
  "end_session_endpoint": "http://localhost:18888/end_session",
  ...
}
```

#### Using the Logout Endpoint

**GET Request:**
```bash
curl "http://localhost:18888/end_session?id_token_hint=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&post_logout_redirect_uri=https://example.com/logout&state=xyz123"
```

**POST Request:**
```bash
curl -X POST http://localhost:18888/end_session \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id_token_hint=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&post_logout_redirect_uri=https://example.com/logout&state=xyz123"
```

#### Parameters

- `id_token_hint` (optional): ID token to identify the user session to terminate
- `post_logout_redirect_uri` (optional): URI to redirect to after logout
- `state` (optional): Opaque value to maintain state between logout request and callback

#### Logout Behavior

1. **Token Invalidation**: All access tokens, refresh tokens, and authorization codes for the user are invalidated
2. **Session Termination**: User session data is cleared
3. **Redirect Handling**: 
   - If `post_logout_redirect_uri` is provided, the user is redirected there
   - If no redirect URI is provided, a logout success page is displayed
4. **State Preservation**: The `state` parameter is passed back in the redirect

#### Security Features

- **URI Validation**: Post-logout redirect URIs are validated for security
- **Token Validation**: ID token hints are validated but invalid tokens don't prevent logout
- **Error Handling**: Proper error responses for invalid requests
- **HTTPS Support**: Supports both HTTP and HTTPS redirect URIs

#### Example Logout Success Page

When no `post_logout_redirect_uri` is provided, users see a styled success page confirming the logout operation.

### CORS Support for Single Page Applications

The OpenID Connect test identity provider includes comprehensive Cross-Origin Resource Sharing (CORS) support for browser-based Single Page Applications (SPAs) like React, Vue.js, and Angular applications.

#### Why CORS is Needed

Browser-based applications running on different ports or domains (e.g., `http://localhost:3000` for React dev server) need CORS headers to make requests to the OIDC server (e.g., `http://localhost:18888`). Without CORS, browsers block these requests for security reasons.

#### CORS Configuration

CORS is **enabled by default** in new configurations and includes common development server ports:

```yaml
# CORS (Cross-Origin Resource Sharing) settings for SPA development
cors:
  enabled: true                           # Enable CORS support
  allowed_origins:                        # List of allowed origins
    - "http://localhost:3000"             # React dev server default port
    - "http://localhost:5173"             # Vite dev server default port
    - "http://localhost:4173"             # Vite preview server port
    - "http://localhost:8080"             # Alternative dev server port
    - "https://localhost:3000"            # HTTPS dev servers
    - "https://localhost:5173"            # HTTPS Vite dev server
  allowed_methods:                        # Allowed HTTP methods
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
    - "HEAD"
  allowed_headers:                        # Allowed request headers
    - "Content-Type"
    - "Authorization"
    - "Accept"
    - "Origin"
    - "X-Requested-With"
```

#### CORS Configuration Options

- **`enabled`**: Enable or disable CORS support (default: `true`)
- **`allowed_origins`**: List of origins that are allowed to make requests
  - Use specific URLs for security: `"http://localhost:3000"`
  - Use `"*"` for wildcard (not recommended for production)
- **`allowed_methods`**: HTTP methods that are allowed in CORS requests
- **`allowed_headers`**: Request headers that are allowed in CORS requests

#### Common Development Server Ports

The default configuration includes common development server ports:

| Framework/Tool | Default Port | HTTPS Port |
|----------------|--------------|------------|
| **React** (Create React App) | `3000` | `3000` |
| **Vite** (Vue, React, etc.) | `5173` | `5173` |
| **Vite Preview** | `4173` | `4173` |
| **Webpack Dev Server** | `8080` | `8080` |
| **Angular CLI** | `4200` | `4200` |

#### Adding Custom Origins

To add your own application origins:

```yaml
cors:
  enabled: true
  allowed_origins:
    - "http://localhost:3000"             # Keep existing
    - "https://myapp.example.com"         # Add production domain
    - "http://localhost:4200"             # Add Angular dev server
    - "http://192.168.1.100:3000"         # Add network access
```

#### CORS Security Features

- **Origin Validation**: Only explicitly allowed origins receive CORS headers
- **Preflight Support**: Handles OPTIONS preflight requests automatically
- **Credential Support**: Includes `Access-Control-Allow-Credentials: true`
- **Header Validation**: Only specified headers are allowed in requests

#### Testing CORS

You can test CORS functionality using curl:

```bash
# Test preflight request
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS \
     http://localhost:18888/.well-known/openid-configuration

# Test actual request with Origin header
curl -H "Origin: http://localhost:3000" \
     http://localhost:18888/.well-known/openid-configuration
```

#### CORS Troubleshooting

**Common Issues:**

1. **CORS Error in Browser Console**
   ```
   Access to fetch at 'http://localhost:18888/...' from origin 'http://localhost:3000' 
   has been blocked by CORS policy
   ```
   **Solution**: Add your origin to `allowed_origins` in the configuration

2. **Missing CORS Headers**
   - Check that `cors.enabled: true` in your configuration
   - Verify your origin is in the `allowed_origins` list
   - Restart the server after configuration changes

3. **Preflight Request Failures**
   - Ensure `OPTIONS` is in `allowed_methods`
   - Check that required headers are in `allowed_headers`

#### Framework-Specific Examples

**React with oidc-client-ts:**
```typescript
// No additional CORS configuration needed in React
// Just ensure your dev server port is in oidcld.yaml
const oidcConfig = {
  authority: 'http://localhost:18888',
  client_id: 'your-client-id',
  redirect_uri: 'http://localhost:3000/callback'
};
```

**Vue.js with oidc-client-ts:**
```typescript
// Vite dev server (port 5173) is included by default
const userManager = new UserManager({
  authority: 'http://localhost:18888',
  client_id: 'your-client-id',
  redirect_uri: 'http://localhost:5173/callback'
});
```

**Angular:**
```yaml
# Add Angular's default port to your oidcld.yaml
cors:
  allowed_origins:
    - "http://localhost:4200"  # Angular CLI default
```

#### Production CORS Configuration

For deployment in test/staging environments, be specific about allowed origins:

```yaml
cors:
  enabled: true
  allowed_origins:
    - "https://myapp-staging.example.com"
    - "https://test.mydomain.com"
  # Remove localhost entries for staging/test environments
```

**Security Best Practices for Testing:**
- Use specific origins instead of `"*"` wildcard
- Use HTTPS origins when possible
- Regularly review and update allowed origins
- Remove development origins from staging/test configurations

## MCP Server Integration

### Installing MCP Server

The OpenID Connect test identity provider can run as an MCP (Model Context Protocol) server to provide configuration management capabilities to AI assistants and development tools.

#### Amazon Q Developer
Add to your MCP configuration:
```json
{
  "mcpServers": {
    "oidcld": {
      "command": "/path/to/oidcld",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

#### Claude Desktop
Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or equivalent:
```json
{
  "mcpServers": {
    "oidcld": {
      "command": "/path/to/oidcld",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

#### VS Code with MCP Extension
Add to your VS Code MCP settings:
```json
{
  "mcp.servers": [
    {
      "name": "oidcld",
      "command": "/path/to/oidcld",
      "args": ["mcp"],
      "cwd": "/path/to/your/project"
    }
  ]
}
```

#### HTTP Mode (for web-based tools)
```bash
./oidcld mcp --port 3001
```
Then configure your MCP client to connect to `http://localhost:3001`

### Available MCP Tools

When running as an MCP server, the following tools are available:

- **`oidcld_init`** - Initialize OpenID Connect configuration
- **`oidcld_query_config`** - Query current configuration settings
- **`oidcld_add_user`** - Add new test users
- **`oidcld_query_users`** - List all configured users
- **`oidcld_modify_config`** - Update configuration settings
- **`oidcld_generate_compose`** - Generate Docker Compose configuration

### Available MCP Resources

- **`config://current`** - Current OpenID Connect configuration
- **`users://list`** - List of all configured users
- **`compose://template`** - Docker Compose template

### Health Check
- **Endpoint**: `GET /health`
- **Expected Response**: Service status confirmation

## CI/CD and Development

### GitHub Actions Workflows

This project includes comprehensive CI/CD pipelines:

#### **Continuous Integration (`ci.yml`)**
- **Triggers**: Pull requests and pushes to main/develop branches
- **Jobs**:
  - **Test**: Runs all unit tests with race detection and coverage reporting
  - **Lint**: Code quality checks with golangci-lint
  - **Security**: Security scanning with Gosec
- **Features**:
  - Go module caching for faster builds
  - Coverage reporting to Codecov
  - Static analysis and security scanning
  - SARIF upload for security findings

#### **Release Pipeline (`release.yml`)**
- **Triggers**: Git tags (v*)
- **Multi-platform Binary Builds**:
  - Windows AMD64 (.exe)
  - macOS ARM64 (Apple Silicon)
  - Linux AMD64
  - Linux ARM64
- **Docker Multi-architecture Images**:
  - `linux/amd64` and `linux/arm64`
  - Published to GitHub Container Registry
  - Automatic tagging (latest, semver)
- **GitHub Releases**:
  - Automatic release creation
  - Binary attachments (zip/tar.gz)
  - Generated release notes

#### **Dependency Management**
- **Dependabot**: Automated dependency updates
- **Auto-merge**: Safe automatic merging of patch/minor updates
- **Weekly Schedule**: Keeps dependencies current

### Development Workflow

1. **Pull Request**: Create PR → CI runs tests and checks
2. **Code Review**: Manual review + automated checks
3. **Merge**: Merge to main triggers additional validation
4. **Release**: Create tag → Automated build and release

### Docker Usage

```bash
# Pull latest image
docker pull ghcr.io/shibukawa/oidcld:latest

# Run with default configuration
docker run -p 18888:18888 ghcr.io/shibukawa/oidcld:latest

# Run with custom configuration
docker run -p 18888:18888 -v $(pwd)/config.yaml:/app/config.yaml \
  ghcr.io/shibukawa/oidcld:latest serve --config /app/config.yaml

# Health check
docker run --rm ghcr.io/shibukawa/oidcld:latest health --url http://host.docker.internal:18888
```

### Advanced Docker Build

The project includes an optimized Dockerfile using BuildX features:

```bash
# Build for local development (single platform)
./scripts/build-docker.sh --load

# Build multi-platform with cache
./scripts/build-docker.sh --platforms linux/amd64,linux/arm64 \
  --cache-from type=gha --cache-to type=gha,mode=max

# Build and push to registry
./scripts/build-docker.sh --name ghcr.io/shibukawa/oidcld \
  --tag v1.0.0 --push
```

**BuildX Features:**
- **Cache Mounts**: Efficient Go module and build caching
- **Bind Mounts**: Source code mounted without copying
- **Multi-platform**: Native ARM64 and AMD64 support
- **Distroless Base**: Secure minimal runtime environment
- **Layer Optimization**: Minimal image size with maximum security

### Build from Source

```bash
# Clone repository
git clone https://github.com/shibukawa/oidcld.git
cd oidcld

# Build binary
go build -o oidcld .

# Run tests
go test ./...

# Build Docker image
docker build -t oidcld .
# OR use build script
./scripts/build-docker.sh --load
```

### Development Tools

**Docker Build Script:**
```bash
./scripts/build-docker.sh --help    # Show usage
./scripts/build-docker.sh --load    # Build for local use
./scripts/build-docker.sh --push    # Build and push multi-platform
```

## Client Integration Examples

### JavaScript/TypeScript Clients

#### oidc-client-ts Integration

```typescript
import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

const config = {
  authority: 'http://localhost:18888',
  client_id: 'your-client-id',
  redirect_uri: 'http://localhost:3000/callback',
  response_type: 'code',
  scope: 'openid profile email',
  post_logout_redirect_uri: 'http://localhost:3000/',
  // Use fragment mode for SPA compatibility
  response_mode: 'fragment',
  userStore: new WebStorageStateStore({ store: window.localStorage })
};

const userManager = new UserManager(config);

// Login
async function login() {
  await userManager.signinRedirect();
}

// Handle callback
async function handleCallback() {
  const user = await userManager.signinRedirectCallback();
  console.log('User logged in:', user);
}

// Logout
async function logout() {
  await userManager.signoutRedirect();
}
```

#### @azure/msal-browser Integration

```typescript
import { PublicClientApplication, Configuration } from '@azure/msal-browser';

const msalConfig: Configuration = {
  auth: {
    clientId: 'your-client-id',
    authority: 'https://localhost:18888', // HTTPS required for MSAL
    redirectUri: 'http://localhost:3000/callback',
  },
  cache: {
    cacheLocation: 'localStorage',
    storeAuthStateInCookie: false,
  }
};

const msalInstance = new PublicClientApplication(msalConfig);

// Login with popup
async function loginPopup() {
  const loginRequest = {
    scopes: ['openid', 'profile', 'email'],
    // MSAL automatically uses fragment mode
  };
  
  const response = await msalInstance.loginPopup(loginRequest);
  console.log('Login successful:', response);
}

// Login with redirect
async function loginRedirect() {
  const loginRequest = {
    scopes: ['openid', 'profile', 'email'],
  };
  
  await msalInstance.loginRedirect(loginRequest);
}

// Handle redirect callback
msalInstance.handleRedirectPromise().then((response) => {
  if (response) {
    console.log('Login successful:', response);
  }
});
```

### Go Client Integration

#### Client Credentials Flow

```go
package main

import (
    "context"
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
    data.Set("client_id", "your-client-id")
    data.Set("client_secret", "your-client-secret")
    data.Set("scope", "read write")
    
    req, err := http.NewRequest(http. MethodPost, tokenURL, strings.NewReader(data.Encode()))
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

func main() {
    token, err := getClientCredentialsToken()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Access Token: %s\n", token.AccessToken)
    fmt.Printf("Token Type: %s\n", token.TokenType)
    fmt.Printf("Expires In: %d seconds\n", token.ExpiresIn)
}
```

#### Device Flow Integration

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type DeviceAuthResponse struct {
    DeviceCode              string `json:"device_code"`
    UserCode                string `json:"user_code"`
    VerificationURI         string `json:"verification_uri"`
    VerificationURIComplete string `json:"verification_uri_complete"`
    ExpiresIn               int    `json:"expires_in"`
    Interval                int    `json:"interval"`
}

type DeviceTokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    IDToken      string `json:"id_token"`
    Error        string `json:"error"`
}

func initiateDeviceFlow() (*DeviceAuthResponse, error) {
    deviceURL := "http://localhost:18888/device"
    
    data := url.Values{}
    data.Set("client_id", "your-client-id")
    data.Set("scope", "openid profile email")
    
    resp, err := http.PostForm(deviceURL, data)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var deviceResp DeviceAuthResponse
    if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
        return nil, err
    }
    
    return &deviceResp, nil
}

func pollForToken(deviceCode string, interval int) (*DeviceTokenResponse, error) {
    tokenURL := "http://localhost:18888/token"
    
    for {
        data := url.Values{}
        data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
        data.Set("device_code", deviceCode)
        data.Set("client_id", "your-client-id")
        
        resp, err := http.PostForm(tokenURL, data)
        if err != nil {
            return nil, err
        }
        
        var tokenResp DeviceTokenResponse
        json.NewDecoder(resp.Body).Decode(&tokenResp)
        resp.Body.Close()
        
        if tokenResp.Error == "" {
            return &tokenResp, nil
        }
        
        if tokenResp.Error == "authorization_pending" {
            time.Sleep(time.Duration(interval) * time.Second)
            continue
        }
        
        return nil, fmt.Errorf("device flow error: %s", tokenResp.Error)
    }
}

func main() {
    // Step 1: Initiate device flow
    deviceAuth, err := initiateDeviceFlow()
    if err != nil {
        fmt.Printf("Error initiating device flow: %v\n", err)
        return
    }
    
    fmt.Printf("Please visit: %s\n", deviceAuth.VerificationURI)
    fmt.Printf("And enter code: %s\n", deviceAuth.UserCode)
    fmt.Printf("Or visit: %s\n", deviceAuth.VerificationURIComplete)
    
    // Step 2: Poll for token
    token, err := pollForToken(deviceAuth.DeviceCode, deviceAuth.Interval)
    if err != nil {
        fmt.Printf("Error getting token: %v\n", err)
        return
    }
    
    fmt.Printf("Access Token: %s\n", token.AccessToken)
    fmt.Printf("ID Token: %s\n", token.IDToken)
}
```

## Azure AD Compatible Mode

### HTTPS Requirement

Azure AD and MSAL libraries require HTTPS for security. Configure OIDCLD with HTTPS support:

```bash
# Generate certificates with mkcert
brew install mkcert  # macOS
mkcert -install
mkcert localhost 127.0.0.1 ::1

# Start OIDCLD with HTTPS
./oidcld --https --cert-file localhost.pem --key-file localhost-key.pem
```

### Azure AD Compatible Configuration

Create an Azure AD compatible configuration:

```yaml
# oidcld.yaml
oidcld:
  issuer: "https://localhost:18888"
  valid_scopes:
    - "openid"
    - "profile"
    - "email"
    - "offline_access"
  pkce_required: true
  nonce_required: true
  expired_in: 3600
  refresh_token_enabled: true
  refresh_token_expiry: 86400
  end_session_enabled: true

# Azure AD compatibility settings
entraid:
  tenant_id: "your-tenant-id"
  version: "v2"  # Use v2 endpoint format

users:
  testuser:
    display_name: "Test User"
    extra_claims:
      email: "test@yourdomain.com"
      preferred_username: "testuser"
      name: "Test User"
      given_name: "Test"
      family_name: "User"
      oid: "12345678-1234-1234-1234-123456789abc"
      tid: "your-tenant-id"
```

### MSAL Configuration for OIDCLD

```typescript
import { PublicClientApplication } from '@azure/msal-browser';

const msalConfig = {
  auth: {
    clientId: 'your-azure-app-id',
    authority: 'https://localhost:18888',  // HTTPS required
    redirectUri: 'https://localhost:3000/callback',
    postLogoutRedirectUri: 'https://localhost:3000/'
  },
  cache: {
    cacheLocation: 'localStorage',
    storeAuthStateInCookie: false,
  }
};

const msalInstance = new PublicClientApplication(msalConfig);

// Login request
const loginRequest = {
  scopes: ['openid', 'profile', 'email'],
  extraScopesToConsent: ['offline_access']  // For refresh tokens
};
```

### Quick Setup Commands

```bash
# Initialize with Azure AD template
./oidcld init --template entraid-v2 --https --mkcert

# Or use interactive setup
./oidcld init
# Select: EntraID/AzureAD v2 template
# HTTPS will be automatically enabled
# Choose to generate mkcert certificates

# Start server
./oidcld --https
```

### Testing Azure AD Compatibility

```bash
# Test discovery endpoint
curl -k https://localhost:18888/.well-known/openid-configuration

# Test authorization endpoint (will redirect to user selection)
curl -k "https://localhost:18888/authorize?response_type=code&client_id=your-app-id&redirect_uri=https://localhost:3000/callback&scope=openid+profile&response_mode=fragment"

# Test JWKS endpoint
curl -k https://localhost:18888/.well-known/jwks.json
```

### Integration Benefits

- **🔒 HTTPS Security**: Required for production-like testing
- **🏢 Enterprise Ready**: Compatible with Azure AD applications
- **📱 MSAL Support**: Works with Microsoft Authentication Library
- **🔄 Refresh Tokens**: Long-lived session support
- **🚪 Logout Support**: Proper session termination
- **📋 Standards Compliant**: Full OpenID Connect and OAuth 2.0 support

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
