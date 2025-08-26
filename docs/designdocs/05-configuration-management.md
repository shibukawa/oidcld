# Configuration Management Design

## Document Information
- **Document Type**: Feature Design Document
- **Version**: 1.0
- **Date**: 2025-06-20
- **Author**: OpenIDLD Team

## Overview

The configuration management system provides flexible, YAML-based configuration for OpenIDLD with support for multiple deployment modes, user management, and cryptographic key handling. This design document outlines the configuration structure, initialization process, and management capabilities.

## Configuration Architecture

### Configuration Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                Configuration System                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │    YAML     │  │ Environment │  │    Command Line     │  │
│  │    File     │  │ Variables   │  │    Arguments        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Configuration Layers                       │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │   OpenID    │ │   EntraID   │ │      Users      │   │  │
│  │  │   Config    │ │   Config    │ │     Config      │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  └─────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │               Validation Layer                          │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │   Schema    │ │   Business  │ │   Cryptographic │   │  │
│  │  │ Validation  │ │   Rules     │ │   Validation    │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Configuration Structure

#### Root Configuration Schema
```yaml
# OpenID Connect Identity Provider Configuration
openidld:
  # Core OpenID Connect settings
  iss: "http://localhost:18888"
  pkce_required: true
  nonce_required: false
  expired_in: 3600
  valid_scopes: ["openid", "profile", "email"]
  algorithm: "RS256"
  private_key_path: ".openidld.key"      # Path to private key file
  public_key_path: ".openidld.pub.key"   # Path to public key file

# EntraID/AzureAD compatibility (optional)
entraid:
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  version: "v2"

# Test user definitions
users:
  admin:
    display_name: "Administrator"
    extra_valid_scopes: ["admin", "read", "write"]
    extra_claims:
      email: "admin@example.com"
      role: "admin"
```

## Configuration Sections

### 1. OpenID Connect Configuration (`openidld`)

#### Core Settings
```yaml
openidld:
  # Issuer identifier (REQUIRED)
  iss: "http://localhost:18888"
  
  # PKCE requirement (OPTIONAL, default: false)
  pkce_required: true
  
  # Nonce requirement (OPTIONAL, default: false)
  nonce_required: false
  
  # Token expiration (OPTIONAL, default: 3600)
  expired_in: 3600  # seconds
  
  # Supported scopes (OPTIONAL)
  # Standard scopes (openid, profile, email) are always included
  valid_scopes:
    - "admin"       # Custom scope for admin access
    - "read"        # Custom scope for read access
    - "write"       # Custom scope for write access
```

#### Cryptographic Settings
```yaml
openidld:
  # JWT signing algorithm (OPTIONAL, default: RS256)
  algorithm: "RS256"  # RS256, RS384, RS512, ES256, ES384, ES512
  
  # Private key file path for JWT signing (OPTIONAL)
  # If empty, generates RSA-2048 key pair at runtime
  private_key_path: ".openidld.key"
  
  # Public key file path for JWT verification (OPTIONAL)  
  # If empty, generates RSA-2048 key pair at runtime
  public_key_path: ".openidld.pub.key"
```

#### Advanced Settings
```yaml
openidld:
  # Custom default claims (OPTIONAL)
  default_claims:
    custom_claim: "default_value"
    organization: "Test Organization"
  
  # CORS settings (OPTIONAL)
  cors_enabled: true
  cors_origins:
    - "http://localhost:3000"
    - "https://myapp.example.com"
  
  # Security settings (OPTIONAL)
  require_https: false  # true for production
  cookie_secure: false  # true for HTTPS
  
  # Rate limiting (OPTIONAL)
  rate_limit_enabled: false
  rate_limit_requests: 100
  rate_limit_window: 60  # seconds
```

### 2. EntraID Configuration (`entraid`)

#### Basic EntraID Settings
```yaml
entraid:
  # Azure AD tenant ID (REQUIRED for EntraID mode)
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  
  # EntraID version (REQUIRED for EntraID mode)
  version: "v2"  # "v1" or "v2"
```

#### EntraID v1.0 Configuration
```yaml
entraid:
  tenant_id: "contoso.onmicrosoft.com"
  version: "v1"
  
  # v1-specific settings
  resource: "https://graph.microsoft.com"
  authority: "https://login.microsoftonline.com"
```

#### EntraID v2.0 Configuration
```yaml
entraid:
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  version: "v2"
  
  # v2-specific settings
  cloud_instance: "https://login.microsoftonline.com"
  graph_endpoint: "https://graph.microsoft.com"
```

### 3. User Configuration (`users`)

#### User Definition Schema
```yaml
users:
  # User ID (key)
  admin:
    # Display name (REQUIRED)
    display_name: "Administrator"
    
    # Additional scopes beyond standard ones (OPTIONAL)
    extra_valid_scopes:
      - "admin"
      - "read"
      - "write"
    
    # Additional JWT claims (OPTIONAL)
    extra_claims:
      email: "admin@example.com"
      given_name: "Admin"
      family_name: "User"
      role: "administrator"
      department: "IT"
      groups: ["admins", "users"]
      employee_id: "EMP001"
```

#### Multiple User Examples
```yaml
users:
  # Administrator with full access
  admin:
    display_name: "Administrator"
    extra_valid_scopes: ["admin", "read", "write"]
    extra_claims:
      email: "admin@example.com"
      role: "administrator"
      department: "IT"
      groups: ["admins", "it-staff"]
  
  # Regular user with limited access
  user:
    display_name: "Regular User"
    extra_valid_scopes: ["read"]
    extra_claims:
      email: "user@example.com"
      role: "user"
      department: "Sales"
      groups: ["users", "sales-team"]
  
  # Test user with minimal claims
  testuser:
    display_name: "Test User"
    extra_claims:
      email: "test@example.com"
      role: "tester"
      groups: ["testers"]
  
  # Service account
  service:
    display_name: "Service Account"
    extra_valid_scopes: ["read", "write"]
    extra_claims:
      email: "service@example.com"
      role: "service"
      account_type: "service"
```

## Configuration Initialization

### Initialization Modes

#### 1. Standard Mode
```bash
./openidld init config.yaml standard
```

**Generated Configuration**:
- Basic OpenID Connect settings
- RSA-2048 key pair
- Standard scopes (openid, profile, email)
- Sample test users
- Local issuer URL

#### 2. EntraID v1 Mode
```bash
./openidld init config.yaml entraid-v1
```

**Generated Configuration**:
- EntraID v1.0 compatible settings
- Microsoft-compatible issuer format
- EntraID-specific claims
- Azure AD tenant configuration
- v1.0 endpoint paths

#### 3. EntraID v2 Mode
```bash
./openidld init config.yaml entraid-v2
```

**Generated Configuration**:
- EntraID v2.0 compatible settings
- Microsoft Graph compatible claims
- Modern Azure AD configuration
- v2.0 endpoint paths
- Enhanced security settings

### Key Generation

#### Runtime Key Generation
When key file paths are not provided or files don't exist, OpenIDLD generates keys at runtime:

```go
func ensureKeys(config *Config) error {
    // Check if key paths are configured and files exist
    if config.OpenIDLD.PrivateKeyPath != "" && config.OpenIDLD.PublicKeyPath != "" {
        if fileExists(config.OpenIDLD.PrivateKeyPath) && fileExists(config.OpenIDLD.PublicKeyPath) {
            return nil // Keys already exist
        }
    }
    
    // Generate new key pair at runtime
    algorithm := config.OpenIDLD.Algorithm
    if algorithm == "" {
        algorithm = "RS256" // Default algorithm
    }
    
    switch {
    case strings.HasPrefix(algorithm, "RS"):
        return generateRSAKeys(config)
    case strings.HasPrefix(algorithm, "ES"):
        return generateECDSAKeys(config)
    default:
        return fmt.Errorf("unsupported algorithm: %s", algorithm)
    }
}

func generateRSAKeys(config *Config) error {
    // Generate RSA key pair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return fmt.Errorf("failed to generate RSA key: %w", err)
    }
    
    // Store keys in memory for runtime use
    config.runtime.privateKey = privateKey
    config.runtime.publicKey = &privateKey.PublicKey
    
    return nil
}
```

#### RSA Key Generation
```go
func generateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, err
    }
    return privateKey, nil
}
```

**Supported Key Sizes**:
- RSA-2048 (default, recommended for testing)
- RSA-3072 (enhanced security)
- RSA-4096 (maximum security)

#### ECDSA Key Generation
```go
func generateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
    privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        return nil, err
    }
    return privateKey, nil
}
```

**Supported Curves**:
- P-256 (ES256, recommended)
- P-384 (ES384)
- P-521 (ES512)

#### Key Serialization
```go
func serializeRSAPrivateKey(key *rsa.PrivateKey) string {
    privateKeyPEM := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(key),
    }
    return string(pem.EncodeToMemory(privateKeyPEM))
}

func serializeRSAPublicKey(key *rsa.PublicKey) string {
    publicKeyPKCS1, _ := x509.MarshalPKCS1PublicKey(key)
    publicKeyPEM := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: publicKeyPKCS1,
    }
    return string(pem.EncodeToMemory(publicKeyPEM))
}
```

## Configuration Validation

### Schema Validation

#### Required Fields Validation
```go
type ValidationRule struct {
    Field    string
    Required bool
    Type     string
    Validator func(interface{}) error
}

var configValidationRules = []ValidationRule{
    {Field: "openidld.iss", Required: true, Type: "string", Validator: validateIssuer},
    {Field: "openidld.algorithm", Required: false, Type: "string", Validator: validateAlgorithm},
    {Field: "openidld.private_key_path", Required: false, Type: "string", Validator: validateKeyPath},
    {Field: "openidld.public_key_path", Required: false, Type: "string", Validator: validateKeyPath},
}
```

#### Business Logic Validation
```go
func validateConfiguration(config *Config) error {
    // Validate issuer URL
    if err := validateIssuerURL(config.OpenIDLD.Issuer); err != nil {
        return fmt.Errorf("invalid issuer: %w", err)
    }
    
    // Validate key pair compatibility
    if err := validateKeyPair(config.OpenIDLD.PrivateKey, config.OpenIDLD.PublicKey); err != nil {
        return fmt.Errorf("invalid key pair: %w", err)
    }
    
    // Validate user definitions
    if err := validateUsers(config.Users); err != nil {
        return fmt.Errorf("invalid users: %w", err)
    }
    
    return nil
}
```

#### Cryptographic Validation
```go
func validateKeyConfiguration(config *Config) error {
    // If key paths are provided, validate they exist and are valid
    if config.OpenIDLD.PrivateKeyPath != "" {
        if err := validateKeyFile(config.OpenIDLD.PrivateKeyPath, "private"); err != nil {
            return fmt.Errorf("invalid private key file: %w", err)
        }
    }
    
    if config.OpenIDLD.PublicKeyPath != "" {
        if err := validateKeyFile(config.OpenIDLD.PublicKeyPath, "public"); err != nil {
            return fmt.Errorf("invalid public key file: %w", err)
        }
    }
    
    // If both paths are provided, verify key pair compatibility
    if config.OpenIDLD.PrivateKeyPath != "" && config.OpenIDLD.PublicKeyPath != "" {
        if err := validateKeyPairFiles(config.OpenIDLD.PrivateKeyPath, config.OpenIDLD.PublicKeyPath); err != nil {
            return fmt.Errorf("key pair mismatch: %w", err)
        }
    }
    
    return nil
}

func validateKeyFile(keyPath, keyType string) error {
    // Check if file exists
    if _, err := os.Stat(keyPath); os.IsNotExist(err) {
        return fmt.Errorf("key file does not exist: %s", keyPath)
    }
    
    // Read and validate key format
    keyData, err := os.ReadFile(keyPath)
    if err != nil {
        return fmt.Errorf("failed to read key file: %w", err)
    }
    
    // Parse key based on type
    if keyType == "private" {
        _, err = parsePrivateKeyFromPEM(keyData)
    } else {
        _, err = parsePublicKeyFromPEM(keyData)
    }
    
    if err != nil {
        return fmt.Errorf("invalid %s key format: %w", keyType, err)
    }
    
    return nil
}
```

### User Validation

#### User Definition Validation
```go
func validateUser(userID string, user User) error {
    // Validate user ID format
    if err := validateUserID(userID); err != nil {
        return fmt.Errorf("invalid user ID: %w", err)
    }
    
    // Validate display name
    if user.DisplayName == "" {
        return fmt.Errorf("display name is required")
    }
    
    // Validate extra scopes
    if err := validateScopes(user.ExtraValidScopes); err != nil {
        return fmt.Errorf("invalid scopes: %w", err)
    }
    
    // Validate extra claims
    if err := validateClaims(user.ExtraClaims); err != nil {
        return fmt.Errorf("invalid claims: %w", err)
    }
    
    return nil
}
```

#### Scope Validation
```go
func validateScopes(scopes []string) error {
    // Standard scopes are always available, no need to validate them
    standardScopes := map[string]bool{
        "openid": true, "profile": true, "email": true,
    }
    
    // Validate custom scopes
    validCustomScopes := map[string]bool{
        "admin": true, "read": true, "write": true,
    }
    
    for _, scope := range scopes {
        // Skip standard scopes (always valid)
        if standardScopes[scope] {
            continue
        }
        
        // Validate custom scopes
        if !validCustomScopes[scope] {
            return fmt.Errorf("unknown custom scope: %s", scope)
        }
    }
    
    return nil
}

func getEffectiveScopes(configuredScopes []string) []string {
    // Always include standard OpenID Connect scopes
    effectiveScopes := []string{"openid", "profile", "email"}
    
    // Add configured custom scopes
    for _, scope := range configuredScopes {
        // Skip if already included (standard scopes)
        if scope == "openid" || scope == "profile" || scope == "email" {
            continue
        }
        effectiveScopes = append(effectiveScopes, scope)
    }
    
    return effectiveScopes
}
```

## Configuration Management Operations

### Loading Configuration

#### File Loading
```go
func LoadConfig(configPath string) (*Config, error) {
    // Read configuration file
    data, err := os.ReadFile(configPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }
    
    // Parse YAML
    var config Config
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    
    // Validate configuration
    if err := validateConfiguration(&config); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }
    
    return &config, nil
}
```

#### Environment Variable Override
```go
func applyEnvironmentOverrides(config *Config) {
    if issuer := os.Getenv("OPENIDLD_ISSUER"); issuer != "" {
        config.OpenIDLD.Issuer = issuer
    }
    
    if port := os.Getenv("PORT"); port != "" {
        // Update issuer port if needed
        updateIssuerPort(config, port)
    }
    
    if algorithm := os.Getenv("OPENIDLD_ALGORITHM"); algorithm != "" {
        config.OpenIDLD.Algorithm = algorithm
    }
}
```

### Saving Configuration

#### Atomic File Writing
```go
func SaveConfig(configPath string, config *Config) error {
    // Validate before saving
    if err := validateConfiguration(config); err != nil {
        return fmt.Errorf("invalid configuration: %w", err)
    }
    
    // Marshal to YAML
    data, err := yaml.Marshal(config)
    if err != nil {
        return fmt.Errorf("failed to marshal config: %w", err)
    }
    
    // Write atomically
    tempFile := configPath + ".tmp"
    if err := os.WriteFile(tempFile, data, 0644); err != nil {
        return fmt.Errorf("failed to write temp file: %w", err)
    }
    
    if err := os.Rename(tempFile, configPath); err != nil {
        os.Remove(tempFile)
        return fmt.Errorf("failed to rename temp file: %w", err)
    }
    
    return nil
}
```

### Configuration Modification

#### User Management
```go
func AddUser(configPath, userID string, user User) error {
    // Load current configuration
    config, err := LoadConfig(configPath)
    if err != nil {
        return err
    }
    
    // Initialize users map if needed
    if config.Users == nil {
        config.Users = make(map[string]User)
    }
    
    // Validate new user
    if err := validateUser(userID, user); err != nil {
        return err
    }
    
    // Add user
    config.Users[userID] = user
    
    // Save configuration
    return SaveConfig(configPath, config)
}

func RemoveUser(configPath, userID string) error {
    config, err := LoadConfig(configPath)
    if err != nil {
        return err
    }
    
    if config.Users == nil {
        return fmt.Errorf("no users configured")
    }
    
    if _, exists := config.Users[userID]; !exists {
        return fmt.Errorf("user %s not found", userID)
    }
    
    delete(config.Users, userID)
    
    return SaveConfig(configPath, config)
}
```

#### Settings Modification
```go
func ModifyConfig(configPath string, updates map[string]interface{}) error {
    config, err := LoadConfig(configPath)
    if err != nil {
        return err
    }
    
    // Apply updates
    for key, value := range updates {
        if err := applyConfigUpdate(config, key, value); err != nil {
            return fmt.Errorf("failed to apply update %s: %w", key, err)
        }
    }
    
    return SaveConfig(configPath, config)
}

func applyConfigUpdate(config *Config, key string, value interface{}) error {
    switch key {
    case "pkce_required":
        if v, ok := value.(bool); ok {
            config.OpenIDLD.PKCERequired = v
        }
    case "nonce_required":
        if v, ok := value.(bool); ok {
            config.OpenIDLD.NonceRequired = v
        }
    case "expired_in":
        config.OpenIDLD.ExpiredIn = value
    case "issuer", "iss":
        if v, ok := value.(string); ok {
            config.OpenIDLD.Issuer = v
        }
    default:
        return fmt.Errorf("unknown configuration key: %s", key)
    }
    return nil
}
```

## Configuration Templates

### Standard Template
```yaml
# Standard OpenID Connect Configuration Template
openidld:
  iss: "http://localhost:18888"
  pkce_required: true
  nonce_required: false
  expired_in: 3600
  # algorithm: "RS256"  # Optional, defaults to RS256
  # Standard scopes (openid, profile, email) are always included
  valid_scopes: ["admin", "read", "write"]  # Optional custom scopes
  private_key_path: ".openidld.key"         # Optional, generates at runtime if empty
  public_key_path: ".openidld.pub.key"     # Optional, generates at runtime if empty

users:
  admin:
    display_name: "Administrator"
    extra_valid_scopes: ["admin", "read", "write"]
    extra_claims:
      email: "admin@example.com"
      role: "admin"
  user:
    display_name: "Regular User"
    extra_valid_scopes: ["read"]
    extra_claims:
      email: "user@example.com"
      role: "user"
  testuser:
    display_name: "Test User"
    extra_claims:
      email: "test@example.com"
```

### EntraID v2 Template
```yaml
# EntraID v2.0 Compatible Configuration Template
openidld:
  iss: "https://login.microsoftonline.com/{{TENANT_ID}}/v2.0"
  pkce_required: true
  nonce_required: true
  expired_in: 3600
  # Standard scopes (openid, profile, email) are always included
  valid_scopes: ["User.Read"]  # Microsoft Graph scopes
  # algorithm: "RS256"  # Optional, defaults to RS256
  private_key_path: ".openidld.key"      # Optional, generates at runtime if empty
  public_key_path: ".openidld.pub.key"   # Optional, generates at runtime if empty

entraid:
  tenant_id: "{{TENANT_ID}}"
  version: "v2"

users:
  admin:
    display_name: "Administrator"
    extra_valid_scopes: ["User.Read", "Directory.Read.All"]
    extra_claims:
      email: "admin@contoso.com"
      preferred_username: "admin@contoso.com"
      oid: "{{ADMIN_OBJECT_ID}}"
      tid: "{{TENANT_ID}}"
      roles: ["Admin", "User"]
```

## Configuration Security

### Sensitive Data Handling

#### Private Key Protection
- **File Permissions**: Restrict configuration file access (600)
- **Memory Protection**: Clear private keys from memory after use
- **Logging**: Never log private key content
- **Backup**: Secure backup procedures for configuration files

#### Configuration Encryption
```go
func encryptConfiguration(config *Config, password string) ([]byte, error) {
    // Serialize configuration
    data, err := yaml.Marshal(config)
    if err != nil {
        return nil, err
    }
    
    // Encrypt with AES-256-GCM
    return encryptAESGCM(data, password)
}

func decryptConfiguration(encryptedData []byte, password string) (*Config, error) {
    // Decrypt data
    data, err := decryptAESGCM(encryptedData, password)
    if err != nil {
        return nil, err
    }
    
    // Parse configuration
    var config Config
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, err
    }
    
    return &config, nil
}
```

### Access Control

#### File System Permissions
```go
func setSecurePermissions(configPath string) error {
    // Set file permissions to 600 (owner read/write only)
    return os.Chmod(configPath, 0600)
}

func validateFilePermissions(configPath string) error {
    info, err := os.Stat(configPath)
    if err != nil {
        return err
    }
    
    mode := info.Mode()
    if mode&0077 != 0 {
        return fmt.Errorf("configuration file has insecure permissions: %o", mode)
    }
    
    return nil
}
```

## Performance Considerations

### Configuration Loading
- **Caching**: In-memory configuration caching
- **File Watching**: Automatic reload on file changes
- **Lazy Loading**: Load configuration sections on demand
- **Validation Caching**: Cache validation results

### Memory Management
- **Key Cleanup**: Clear private keys from memory
- **Configuration Cleanup**: Release unused configuration data
- **Garbage Collection**: Efficient memory usage patterns
- **Resource Limits**: Bounded memory usage

### Concurrent Access
- **Read-Write Locks**: Protect configuration during updates
- **Atomic Operations**: Atomic configuration updates
- **Copy-on-Write**: Efficient configuration sharing
- **Lock-Free Reads**: Optimized read operations


