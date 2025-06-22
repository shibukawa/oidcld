# Client Credentials Flow Example

A simple example demonstrating the OAuth 2.0 Client Credentials flow using the OpenID Foundation certified OIDC client library with the oidcld test identity provider.

## Requirements

- Go 1.24 or later
- Running oidcld server (default configuration)

## Docker Usage

### Using Docker Compose (Recommended)

1. **Start the OIDC server only:**
   ```bash
   docker compose up oidcld
   ```

2. **Run the client credentials example:**
   ```bash
   docker compose --profile example up --build
   ```

3. **Run with custom parameters:**
   ```bash
   docker compose run --rm client-credentials-example --client-id custom-client
   ```

4. **Clean up:**
   ```bash
   docker compose down
   ```

### Using Docker Build

1. **Build the image:**
   ```bash
   docker build -t client-credentials-example .
   ```

2. **Run with oidcld server:**
   ```bash
   # Start oidcld server first
   docker run -d --name oidcld -p 18888:18888 ghcr.io/shibukawa/oidcld:latest
   
   # Run the example
   docker run --rm --network container:oidcld client-credentials-example \
     --idp-host http://localhost:18888 --client-id my-client-app
   ```

### Docker Features

- **Multi-stage Build**: Optimized for size and security
- **Distroless Base**: Minimal attack surface with gcr.io/distroless/base-debian12:nonroot
- **BuildX Cache**: Efficient builds with Go module and build caching
- **Health Checks**: Automatic service dependency management
- **Network Isolation**: Dedicated Docker network for service communication

## Quick Start

1. Start the oidcld server:
   ```bash
   cd ../..
   ./oidcld serve
   ```

2. Build and run the example:
   ```bash
   go build -o client-credentials-example
   ./client-credentials-example
   ```

## Usage

### Basic Usage
```bash
# Use default settings (works with default oidcld.yaml)
./client-credentials-example

# Specify different Identity Provider host
./client-credentials-example --idp-host http://localhost:8080

# Specify OAuth 2.0 client ID
./client-credentials-example --client-id my-client-app

# Combined usage
./client-credentials-example --idp-host http://localhost:18888 --client-id my-client-app
```

### Command Line Options

- `--idp-host`: OIDC server URL (default: http://localhost:18888)
- `--client-id`: OAuth 2.0 Client ID (default: my-client-app)

### Example Output

```bash
$ ./client-credentials-example --client-id my-client-app
Using OIDC server: http://localhost:18888
Client ID: my-client-app
Requesting token...
Success!
Access Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Token Type: Bearer
Expires In: 3600 seconds
```

## How It Works

This example uses the OpenID Foundation certified OIDC client library (`github.com/zitadel/oidc/v3`) to:

1. **Discover** the OIDC server endpoints automatically
2. **Create** a certified OIDC client with the specified parameters
3. **Request** an access token using the Client Credentials flow
4. **Display** the token information

## Default Configuration Compatibility

This example works out-of-the-box with the default oidcld configuration:

```yaml
oidcld:
  valid_audiences:
    - "my-client-app"
  valid_scopes:
    - "read"
    - "write"
```

**Note**: In oidcld, the `client-id` parameter corresponds to user names in the YAML configuration. This example treats it as a standard OAuth 2.0 client identifier for compliance with OAuth 2.0 terminology.

## Testing

Run the unit tests:

```bash
go test -v
```

## Dependencies

- **github.com/zitadel/oidc/v3**: OpenID Foundation certified OIDC client library
- **Standard Go libraries**: flag, fmt, log, context, net/url, time

## Standards Compliance

This example demonstrates proper OAuth 2.0 Client Credentials flow implementation using an OpenID Foundation certified client library, ensuring standards compliance and best practices.
