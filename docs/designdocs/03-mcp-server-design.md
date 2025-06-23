# MCP Server Design

## Document Information
- **Document Type**: Feature Design Document
- **Version**: 1.0
- **Date**: 2025-06-20
- **Author**: OpenIDLD Team

## Overview

The Model Context Protocol (MCP) server implementation enables OpenIDLD to integrate with AI assistants, development tools, and automation systems. This design document outlines the MCP server architecture, tools, resources, and integration patterns.

## MCP Protocol Overview

### What is MCP?
- **Purpose**: Standardized protocol for AI assistants to interact with external systems
- **Architecture**: Client-server model with JSON-RPC communication
- **Transport**: stdin/stdout or HTTP
- **Capabilities**: Tools (actions) and Resources (data access)

### OpenIDLD MCP Integration
- **Role**: MCP Server providing OpenID Connect configuration management
- **Clients**: AI assistants (Amazon Q, Claude), IDEs, automation tools
- **Value**: Programmatic configuration management and testing automation

## Architecture Design

### MCP Server Modes

#### 1. stdin/stdout Mode (Default)
```bash
./openidld mcp
```
- **Transport**: Standard input/output streams
- **Use Case**: AI assistant integration, local development
- **Protocol**: JSON-RPC over stdio
- **Lifecycle**: Long-running process with persistent connection

#### 2. HTTP Server Mode
```bash
./openidld mcp --port 3001
```
- **Transport**: HTTP with JSON-RPC payload
- **Use Case**: Web-based tools, remote automation
- **Protocol**: JSON-RPC over HTTP POST
- **Lifecycle**: HTTP server accepting multiple connections

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Server                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   stdio     │  │    HTTP     │  │      Protocol       │  │
│  │  Transport  │  │  Transport  │  │      Handler        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                 MCP Core Engine                         │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │    Tool     │ │  Resource   │ │    Request      │   │  │
│  │  │   Registry  │ │   Registry  │ │    Router       │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  └─────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Configuration Interface                    │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │  │
│  │  │    YAML     │ │    User     │ │     Docker      │   │  │
│  │  │   Config    │ │ Management  │ │    Compose      │   │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────┘   │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## MCP Tools Design

### Tool Categories

#### 1. Configuration Management Tools
- **Purpose**: Initialize and modify OpenID Connect configuration
- **Scope**: YAML file manipulation, validation
- **Security**: File system access with validation

#### 2. User Management Tools
- **Purpose**: Add, modify, and query test users
- **Scope**: User definition and scope management
- **Security**: Configuration validation and sanitization

#### 3. Infrastructure Tools
- **Purpose**: Generate deployment configurations
- **Scope**: Docker Compose, Kubernetes manifests
- **Security**: Template-based generation with validation

### Tool Specifications

#### 1. openidld_init
```json
{
  "name": "openidld_init",
  "description": "Initialize OpenID Connect configuration",
  "inputSchema": {
    "type": "object",
    "properties": {
      "config_path": {
        "type": "string",
        "description": "Path to configuration file"
      },
      "mode": {
        "type": "string",
        "description": "Configuration mode",
        "enum": ["standard", "entraid-v1", "entraid-v2"],
        "default": "standard"
      }
    },
    "required": ["config_path"]
  }
}
```

**Implementation**:
- Generate RSA/ECDSA key pairs
- Create mode-specific configuration
- Write YAML configuration file
- Validate configuration structure

#### 2. openidld_query_config
```json
{
  "name": "openidld_query_config",
  "description": "Query current OpenID Connect configuration",
  "inputSchema": {
    "type": "object",
    "properties": {
      "config_path": {
        "type": "string",
        "description": "Path to configuration file"
      }
    },
    "required": ["config_path"]
  }
}
```

**Implementation**:
- Load and parse YAML configuration
- Return structured configuration data
- Mask sensitive information (private keys)
- Validate configuration integrity

#### 3. openidld_add_user
```json
{
  "name": "openidld_add_user",
  "description": "Add a new test user",
  "inputSchema": {
    "type": "object",
    "properties": {
      "config_path": {"type": "string"},
      "user_id": {"type": "string"},
      "display_name": {"type": "string"},
      "extra_valid_scopes": {
        "type": "array",
        "items": {"type": "string"}
      },
      "extra_claims": {"type": "object"}
    },
    "required": ["config_path", "user_id", "display_name"]
  }
}
```

**Implementation**:
- Validate user ID uniqueness
- Validate scope permissions
- Sanitize extra claims
- Update configuration file atomically

#### 4. openidld_query_users
```json
{
  "name": "openidld_query_users",
  "description": "List all configured users",
  "inputSchema": {
    "type": "object",
    "properties": {
      "config_path": {"type": "string"}
    },
    "required": ["config_path"]
  }
}
```

**Implementation**:
- Load user configuration
- Return user list with metadata
- Include scope and claim information
- Mask sensitive user data

#### 5. openidld_modify_config
```json
{
  "name": "openidld_modify_config",
  "description": "Modify OpenID Connect configuration settings",
  "inputSchema": {
    "type": "object",
    "properties": {
      "config_path": {"type": "string"},
      "updates": {
        "type": "object",
        "description": "Configuration updates to apply"
      }
    },
    "required": ["config_path", "updates"]
  }
}
```

**Implementation**:
- Validate update parameters
- Apply configuration changes
- Preserve existing settings
- Validate final configuration

#### 6. openidld_generate_compose
```json
{
  "name": "openidld_generate_compose",
  "description": "Generate Docker Compose configuration",
  "inputSchema": {
    "type": "object",
    "properties": {
      "config_path": {"type": "string"},
      "compose_path": {"type": "string"}
    },
    "required": ["config_path"]
  }
}
```

**Implementation**:
- Generate Docker Compose YAML
- Include volume mounts for configuration
- Configure networking and ports
- Add example application services

## MCP Resources Design

### Resource Categories

#### 1. Configuration Resources
- **Purpose**: Expose current configuration state
- **Access**: Read-only configuration data
- **Format**: YAML and JSON representations

#### 2. User Resources
- **Purpose**: Expose user definitions and metadata
- **Access**: Read-only user information
- **Format**: JSON with user details

#### 3. Template Resources
- **Purpose**: Provide deployment templates
- **Access**: Static template content
- **Format**: YAML templates for various platforms

### Resource Specifications

#### 1. config://current
```json
{
  "uri": "config://current",
  "name": "Current Configuration",
  "description": "Current OpenID Connect configuration",
  "mimeType": "application/yaml"
}
```

**Implementation**:
- Read current configuration file
- Return raw YAML content
- Include metadata about last modification
- Validate configuration before serving

#### 2. users://list
```json
{
  "uri": "users://list",
  "name": "User List",
  "description": "List of all configured users",
  "mimeType": "application/json"
}
```

**Implementation**:
- Extract user definitions from configuration
- Format as JSON with user metadata
- Include scope and claim information
- Exclude sensitive information

#### 3. compose://template
```json
{
  "uri": "compose://template",
  "name": "Docker Compose Template",
  "description": "Docker Compose template for OpenID Connect server",
  "mimeType": "application/yaml"
}
```

**Implementation**:
- Return static Docker Compose template
- Include configuration volume mounts
- Provide example application service
- Include networking and port configuration

## Integration Patterns

### AI Assistant Integration

#### Amazon Q Developer
```json
{
  "mcpServers": {
    "openidld": {
      "command": "/path/to/openidld",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

**Use Cases**:
- "Initialize OpenID Connect configuration for testing"
- "Add a test user with admin privileges"
- "Generate Docker Compose for the current setup"
- "Show me the current user configuration"

#### Claude Desktop
```json
{
  "mcpServers": {
    "openidld": {
      "command": "/path/to/openidld",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

**Use Cases**:
- Configuration management through natural language
- Automated test user creation
- Infrastructure template generation
- Configuration validation and troubleshooting

#### VS Code Integration
```json
{
  "mcp.servers": [
    {
      "name": "openidld",
      "command": "/path/to/openidld",
      "args": ["mcp"],
      "cwd": "/path/to/project"
    }
  ]
}
```

**Use Cases**:
- IDE-integrated configuration management
- Project-specific OpenID Connect setup
- Automated testing configuration
- Development workflow integration

### Automation Integration

#### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: Setup OpenID Connect Test Environment
  run: |
    ./openidld mcp --port 3001 &
    curl -X POST http://localhost:3001 \
      -H "Content-Type: application/json" \
      -d '{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
          "name": "openidld_init",
          "arguments": {
            "config_path": "test-config.yaml",
            "mode": "standard"
          }
        }
      }'
```

#### Infrastructure as Code
```python
# Python automation example
import requests
import json

def setup_openid_test_env():
    mcp_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "openidld_init",
            "arguments": {
                "config_path": "config.yaml",
                "mode": "entraid-v2"
            }
        }
    }
    
    response = requests.post(
        "http://localhost:3001",
        json=mcp_request
    )
    return response.json()
```

## Security Design

### Access Control
- **File System**: Limited to configuration directory
- **Validation**: Input sanitization and validation
- **Permissions**: Read/write access to configuration files only

### Input Validation
- **Schema Validation**: JSON Schema validation for all inputs
- **Path Validation**: Prevent directory traversal attacks
- **Content Validation**: YAML and JSON structure validation
- **Size Limits**: Prevent resource exhaustion attacks

### Error Handling
- **Information Disclosure**: Sanitized error messages
- **Logging**: Comprehensive audit logging
- **Rate Limiting**: Optional rate limiting for HTTP mode
- **Resource Limits**: Memory and CPU usage limits

## Performance Considerations

### Request Processing
- **Latency**: <100ms for typical operations
- **Throughput**: 50+ requests/second
- **Memory**: Minimal memory footprint
- **CPU**: Efficient YAML/JSON processing

### Caching Strategy
- **Configuration Caching**: In-memory configuration cache
- **Template Caching**: Static template caching
- **Validation Caching**: Schema validation caching
- **Invalidation**: File modification-based invalidation

### Resource Management
- **Connection Limits**: Configurable connection limits
- **Memory Limits**: Bounded memory usage
- **File Handles**: Efficient file handle management
- **Goroutine Management**: Controlled concurrency

## Error Handling and Resilience

### MCP Protocol Errors
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "parameter": "config_path",
      "reason": "File not found"
    }
  }
}
```

### Error Categories
- **-32700**: Parse error (malformed JSON)
- **-32600**: Invalid request (missing required fields)
- **-32601**: Method not found (unknown tool/resource)
- **-32602**: Invalid params (parameter validation failure)
- **-32603**: Internal error (server-side errors)

### Resilience Patterns
- **Graceful Degradation**: Continue operation with limited functionality
- **Circuit Breaker**: Prevent cascading failures
- **Retry Logic**: Automatic retry for transient failures
- **Health Checks**: Built-in health monitoring

## Testing Strategy

### Unit Testing
- **Tool Testing**: Individual tool function testing
- **Resource Testing**: Resource access and formatting
- **Protocol Testing**: MCP protocol compliance
- **Error Testing**: Error handling and edge cases

### Integration Testing
- **Client Integration**: Real MCP client testing
- **End-to-End**: Complete workflow testing
- **Performance Testing**: Load and stress testing
- **Security Testing**: Input validation and access control

### Compliance Testing
- **MCP Specification**: Protocol compliance validation
- **JSON-RPC**: JSON-RPC 2.0 compliance
- **Schema Validation**: Input/output schema validation
- **Interoperability**: Multiple client compatibility



