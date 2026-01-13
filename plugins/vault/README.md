# Vault Plugin

The Vault plugin generates bearer tokens from vault-saved tokens based on OAuth2 configuration protecting a tool.
It receives a dictionary of secrets and use them to dispatch the authorization token to the server based on rules.

## Features

- **Tag-based metadata handling**: Supports dict format `{"id": "...", "label": "..."}`
   - Supported tags must be created on an MCP server to drive the secret handling:
        - system:<system host> where system host is the IDP provider for that MCP Server. For example system:github.com or system:mural.com
        - AUTH_HEADER:<header name> where header name is the authorization header to be used for this MCP header if a PAT token is send

- **Complex token key format**: Supports secrets send via a  header containing a JSON dictionary with keys like `github.com:USER:OAUTH2:TOKEN` or simple `github.com`
- **PAT (Personal Access Token) support**: Use `AUTH_HEADER` tag to specify a custom header to be dispatched to the backend server.
- **OAuth2 token support**: Default bearer token handling for OAuth2 tokens. If no specific rule for PAT the default behavior is to send the secret as Bearer token in Authorization header
- **Flexible configuration**: Falls back to default bearer token behavior when parts are missing

## Configuration

### Basic Configuration (RAW Mode)

```yaml
vault:
  enabled: true
  config:
    system_tag_prefix: "system"
    vault_header_name: "X-Vault-Tokens"
    vault_handling: "raw"
    system_handling: "tag"
    auth_header_tag_prefix: "AUTH_HEADER"
```

### UNWRAP Mode Configuration

```yaml
vault:
  enabled: true
  config:
    system_tag_prefix: "system"
    vault_header_name: "X-Vault-Tokens"
    vault_session_header: "X-Vault-Session-ID"
    vault_handling: "unwrap"
    system_handling: "tag"
    auth_header_tag_prefix: "AUTH_HEADER"
    unwrap_cache_ttl_seconds: 600.0
    encrypt_cache: true  # Enable encryption for cached tokens (default: true)
    cache_encryption_key: null  # Optional: custom encryption key (defaults to JWT_SECRET_KEY)
```

**Environment Variables Required for UNWRAP Mode:**
```bash
# Redis configuration (required for distributed caching)
CACHE_TYPE=redis
REDIS_URL=redis://localhost:6379

# Vault proxy configuration
VAULT_PROXY_URL=https://vault-proxy.example.com
VAULT_API_KEY=your-api-key
```

### Configuration Options

- **system_tag_prefix**: Prefix for system identification tags (default: `"system"`)
- **vault_header_name**: HTTP header name for vault tokens (default: `"X-Vault-Tokens"`)
- **vault_session_header**: HTTP header name for session ID (default: `"X-Vault-Session-ID"`, required for UNWRAP mode)
- **vault_handling**: Token handling mode - `"raw"` or `"unwrap"` (default: `"raw"`)
  - **raw**: Use token as-is from vault
  - **unwrap**: Unwrap single-use tokens from vault proxy with distributed caching
- **system_handling**: System identification mode (default: `"tag"`)
- **auth_header_tag_prefix**: Prefix for auth header tags (default: `"AUTH_HEADER"`)
- **unwrap_cache_ttl_seconds**: TTL for unwrapped token cache in seconds (default: `600.0`, only used in UNWRAP mode)
- **encrypt_cache**: Enable encryption for cached tokens (default: `true`)
- **cache_encryption_key**: Custom encryption key for cache (default: uses `JWT_SECRET_KEY` from settings)

## Token Key Format

The plugin supports complex token keys in the format:

```
system[:scope][:token_type][:token_name]
```

Where:
- **system** (required): The system identifier (e.g., `github.com`, `gitlab.com`)
- **scope** (optional): USER or GROUP (ignored in processing)
- **token_type** (optional): PAT or OAUTH2
- **token_name** (optional): Name of the token

### Examples

1. **Simple key**: `github.com`
   - Uses default OAuth2 bearer token handling

2. **Full PAT key**: `github.com:USER:PAT:my-token`
   - System: `github.com`
   - Scope: `USER` (ignored)
   - Token type: `PAT`
   - Token name: `my-token`
   - Checks for `AUTH_HEADER` tag to determine header name

3. **OAuth2 key**: `gitlab.com:GROUP:OAUTH2:app-token`
   - System: `gitlab.com`
   - Scope: `GROUP` (ignored)
   - Token type: `OAUTH2`
   - Token name: `TOKEN` (default name)
   - Uses OAuth2 bearer token handling

## Vault Handling Modes

### RAW Mode (Default)

Uses tokens as-is from the vault header:
```yaml
vault_handling: "raw"
```

Tokens are passed directly without any transformation.

### UNWRAP Mode

Unwraps single-use wrapped tokens from vault proxy with distributed caching:
```yaml
vault_handling: "unwrap"
vault_session_header: "X-Vault-Session-ID"
unwrap_cache_ttl_seconds: 600.0
```

**⚠️ IMPORTANT: New Header Required**

UNWRAP mode requires agents to send an additional header with each request:
- **Header Name**: `X-Vault-Session-ID` (configurable via `vault_session_header`)
- **Value**: Unique session identifier (e.g., agent chat ID, MCP session ID)
- **Purpose**: Scopes token caching to specific sessions
- **Example**: `X-Vault-Session-ID: agent-chat-session-123`

**Without this header, requests will fail with an error.**

**Features:**
- **Single-use tokens**: Vault wrapped tokens can only be unwrapped once
- **Session-scoped caching**: Unwrapped tokens cached per session to avoid re-unwrapping
- **Distributed locking**: Redis-based locks prevent duplicate unwrapping across gateway instances
- **Automatic fallback**: Falls back to direct unwrap if Redis unavailable

**Requirements:**
- ✅ Redis must be configured (`cache_type: redis`)
- ✅ Agent must send `X-Vault-Session-ID` header with unique session identifier
- ✅ Vault proxy must be accessible via `VAULT_PROXY_URL` environment variable

**How it works:**
1. Agent sends wrapped token + session ID
2. Plugin checks Redis cache for unwrapped token
3. If cache miss, acquires distributed lock
4. Unwraps token via vault proxy
5. Caches unwrapped token in Redis (TTL: 600s default)
6. Subsequent requests in same session use cached token

**Example Request (UNWRAP Mode):**
```http
POST /api/tools/invoke
X-Vault-Session-ID: agent-chat-session-123
X-Vault-Tokens: {"github.com": "wrapped_token_xyz"}
```

**⚠️ Note**: Both headers are required:
1. `X-Vault-Session-ID` - Session identifier (NEW for UNWRAP mode)
2. `X-Vault-Tokens` - Wrapped tokens dictionary (existing)

**Example Request (RAW Mode):**
```http
POST /api/tools/invoke
X-Vault-Tokens: {"github.com": "raw_token_abc"}
```

**Note**: RAW mode only needs `X-Vault-Tokens` header (no session ID required)

**Performance:**
- First call: +50-100ms (unwrap + cache write)
- Cached calls: <5ms (Redis lookup)
- Cache hit rate: >90% for typical workloads

## Token Type Handling

**Note**: The `vault_handling` setting (`raw` or `unwrap`) applies to **ALL token types**. Unwrapping happens first (if enabled), then the token is set according to its type.

### Processing Flow

1. **Unwrap (if enabled)**: If `vault_handling: "unwrap"`, unwrap the token first
2. **Set Header**: Set the appropriate header based on token type

### PAT (Personal Access Token)

When `token_type` is `PAT`:
1. **Unwrap**: If UNWRAP mode, unwrap token first
2. **Set Header**:
   - If AUTH_HEADER tag exists: Use custom header (e.g., `X-GitHub-Token`)
   - Otherwise: Use `Authorization: Bearer <token>`

**Example:**
```yaml
# Token key: "github.com:USER:PAT:my-token"
# With AUTH_HEADER:X-GitHub-Token tag
# Result: X-GitHub-Token: <unwrapped_or_raw_token>
```

### OAUTH2

When `token_type` is `OAUTH2` or missing:
1. **Unwrap**: If UNWRAP mode, unwrap token first
2. **Set Header**: Always uses `Authorization: Bearer <token>`

**Example:**
```yaml
# Token key: "github.com:USER:OAUTH2:TOKEN" or "github.com"
# Result: Authorization: Bearer <unwrapped_or_raw_token>
```

### Unknown Types

For any other token type:
1. **Unwrap**: If UNWRAP mode, unwrap token first
2. **Set Header**: Falls back to `Authorization: Bearer <token>`
3. **Warning**: Logs warning about unknown token type

## Security

### Cache Encryption

**Enabled by default** in UNWRAP mode to protect sensitive tokens stored in Redis cache.

#### How It Works

1. **Encryption Algorithm**: Uses Fernet (symmetric encryption) with Argon2id key derivation
2. **Key Source**: 
   - Custom key via `cache_encryption_key` config (recommended for production)
   - Falls back to `JWT_SECRET_KEY` from gateway settings
3. **Encryption Process**:
   - Token is encrypted before storing in Redis
   - Encrypted data includes salt and KDF parameters in JSON bundle
   - Decryption happens automatically on cache retrieval

#### Configuration

**Default (Encryption Enabled):**
```yaml
vault:
  config:
    encrypt_cache: true  # Default
    # Uses JWT_SECRET_KEY automatically
```

**Custom Encryption Key:**
```yaml
vault:
  config:
    encrypt_cache: true
    cache_encryption_key: "your-strong-encryption-key-here"
```

**Disable Encryption (Not Recommended):**
```yaml
vault:
  config:
    encrypt_cache: false  # Tokens stored in plain text in Redis
```

#### Security Benefits

- **At-Rest Protection**: Tokens encrypted in Redis cache
- **Key Rotation**: Change `cache_encryption_key` to invalidate all cached tokens
- **Argon2id KDF**: Memory-hard key derivation resistant to GPU attacks
- **Graceful Degradation**: Falls back to plain text if encryption fails (with error logging)

#### Performance Impact

- **First cache write**: +2-5ms (encryption overhead)
- **Cache read**: +1-3ms (decryption overhead)
- **Negligible** compared to network latency and vault unwrap time

#### Best Practices

1. **Use dedicated encryption key** separate from JWT secret
2. **Rotate keys periodically** (invalidates cache, forces re-unwrap)
3. **Monitor logs** for encryption/decryption failures
4. **Keep encryption enabled** in production environments
5. **Secure Redis** with TLS and authentication


## Gateway Metadata Tags

The plugin handles tags in dict format:

```json
{
  "tags": [
    {"id": "auto-generated-id", "label": "system:github.com"},
    {"id": "another-id", "label": "AUTH_HEADER:X-GitHub-Token"},
    {"id": "third-id", "label": "environment:production"}
  ]
}
```

The plugin extracts the `label` field from dict tags (the actual tag value), while `id` is autogenerated.

### Tag Types

1. **System Tag**: `system:<system_name>`
   - Identifies which system the token is for
   - Example: `system:github.com`
   - Required for the plugin to work

2. **Auth Header Tag**: `AUTH_HEADER:<header_name>`
   - Specifies custom header for PAT tokens
   - Example: `AUTH_HEADER:X-GitHub-Token`
   - Only used when token type is PAT
   - Optional - falls back to Bearer token if not present

## Example Usage

### Request with Vault Tokens

```http
POST /api/tools/invoke
X-Vault-Tokens: {"github.com:USER:PAT:my-token": "ghp_xxxxxxxxxxxx", "gitlab.com": "glpat-yyyyyyyy"}
```

### Gateway with AUTH_HEADER Tag

If gateway has tags including `AUTH_HEADER:X-GitHub-Token`:
```json
{
  "tags": [
    {"id": "1", "label": "system:github.com"},
    {"id": "2", "label": "AUTH_HEADER:X-GitHub-Token"}
  ]
}
```

The plugin will set:
```http
X-GitHub-Token: ghp_xxxxxxxxxxxx
```

### Without AUTH_HEADER Tag

If no `AUTH_HEADER` tag is defined, the plugin will use default Bearer token:
```http
Authorization: Bearer ghp_xxxxxxxxxxxx
```

## System Identification

The plugin supports two modes for identifying the system, configured via the `system_handling` parameter in plugin config:

### TAG Mode (Default)

**Configuration**: `system_handling: "tag"`

Extracts system from gateway tags with the configured prefix:
- Tag: `system:github.com` → System: `github.com`
- Requires gateway to have tags like `system:<hostname>`

**Example:**
```yaml
vault:
  config:
    system_handling: "tag"  # Default mode
    system_tag_prefix: "system"
```

### OAUTH2_CONFIG Mode

**Configuration**: `system_handling: "oauth2_config"`

Extracts system from the OAuth2 configuration's `token_url`:
- Token URL: `https://github.com/login/oauth/access_token` → System: `github.com`
- Requires gateway to have OAuth2 configuration with `token_url`

**Example:**
```yaml
vault:
  config:
    system_handling: "oauth2_config"  # Extract from OAuth2 config
```

**Note**: Both modes determine which system the token is for, enabling the plugin to match tokens from the `X-Vault-Tokens` header to the appropriate backend system.

## Hook

- **tool_pre_invoke**: Processes vault tokens before tool invocation


## Testing

## Create a token
export MCPGATEWAY_BEARER_TOKEN = python3 -m mcpgateway.utils.create_jwt_token --username admin@example.com --exp 10080 --secret my-test-key

export CLIENT_ID=xxx
export CLIENT_SECRET=xxx


## Register MCP server with the gateway and add OAuth2 configuration Using UI
curl -s -X POST -H "Authorization: Bearer $MCPGATEWAY_BEARER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
           "name": "github_com",
           "url": "https://api.githubcopilot.com/mcp/",
           "description": "A new MCP server added with OAuth2 authentication",
           "auth_type": "oauth",
           "auth_value": {
             "client_id": "'$CLIENT_ID'",
             "client_secret": "'$CLIENT_SECRET'",
             "token_url": "https://github.com/login/oauth/access_token",
             "redirect_url": "http://localhost:4444/oauth/callback"
           },
           "tags": ["system:github.com"],
           "passthrough_headers": ["X-Vault-Tokens"]
         }' \
     http://localhost:4444/gateways

## Invocation
When the server is configured invoke the server and send a pass through header of form

    "X-Vault-Tokens": {
        "github.com": "key"
    },

## Sample of Invoking a Tool on the Added Gateway

```bash
# Invoke a tool on the added gateway
curl -s -X POST -H "Authorization: Bearer $MCPGATEWAY_BEARER_TOKEN" \
     -H "Content-Type: application/json" \
     -H 'X-Vault-Tokens: "{\"github.com\": \"key\"}"' \
     -d '{
           "tool_name": "github-com-list-issues",
           "arguments": {
             "repo": "reponame"
           }
         }' \
     http://localhost:4444/tools/invoke
```
