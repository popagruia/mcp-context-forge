# Vault Plugin E2E Test

This directory contains an end-to-end test for the Vault plugin that validates token unwrapping and caching functionality with real Redis.

## Overview

The Vault plugin e2e test validates:
1. **Token Unwrapping**: Wrapped tokens from HashiCorp Vault are unwrapped to retrieve actual secrets
2. **Redis Caching**: Unwrapped tokens are cached per session to avoid re-unwrapping
3. **Single-use Enforcement**: Wrapped tokens can only be unwrapped once
4. **Header Transformation**: Vault headers are removed and Authorization headers are added
5. **Multi-call Sessions**: Multiple tool calls within the same session reuse cached tokens

## Test Architecture

```
┌─────────────────┐
│   Test Suite    │
│  (pytest-asyncio)│
└────────┬────────┘
         │
         │ Direct call to plugin hook
         v
┌────────────────┐                    ┌──────────────┐
│  Vault Plugin  │◄──────────────────►│    Redis     │
│ (on_tool_call) │   Token Caching    │  (docker)    │
└────────┬───────┘                    └──────────────┘
         │
         │ Mock Vault Unwrap
         v
┌────────────────┐
│  MockVaultProxy│
│  (unittest.mock)│
└────────────────┘
```

**Key Design**: This test directly calls the vault plugin's `on_tool_call_request` hook without launching an MCP server, making it fast and reliable while still testing all core functionality.

## Prerequisites

### 1. Start Docker Compose Services

The e2e test requires Redis to be running. Use the existing docker-compose setup:

```bash
# Start Redis (and optionally other services)
docker-compose up -d redis

# Verify Redis is running
docker-compose ps redis
```

### 2. Install Test Dependencies

```bash
# Install dev dependencies (includes pytest, httpx, etc.)
make install-dev

# Or with uv directly
uv pip install -e ".[dev]"
```

## Running the Test

### Quick Start

```bash
# From project root
pytest tests/e2e/test_vault_plugin_redis_only.py -v -s
```

### With Setup Script

```bash
# Run setup script (starts Redis, verifies connection)
./tests/e2e/setup_vault_test.sh

# Run test
pytest tests/e2e/test_vault_plugin_redis_only.py -v -s
```

### With Coverage

```bash
pytest tests/e2e/test_vault_plugin_redis_only.py --cov=plugins.vault --cov-report=html
```

## Test Configuration

Environment variables are configured in `pyproject.toml` via pytest-env plugin:

```toml
[tool.pytest.ini_options]
env = [
    "REDIS_URL=redis://localhost:6379/0",
    "CACHE_TYPE=redis",
    "VAULT_PROXY_URL=http://mock-vault:8200",
    "VAULT_API_KEY=test-vault-api-key-12345",
    "PLUGINS_ENABLED=true"
]
```

These are set BEFORE any imports, ensuring the config module loads with correct values.

## Test Flow

### Test: `test_vault_plugin_unwrap_and_cache`

1. **Setup**:
   - MockVaultProxy with wrapped token `hvs.wrapped_localhost_token`
   - Redis connection verified
   - Vault plugin initialized with UNWRAP mode

2. **First Call** (session_id: `test-session-123`):
   ```python
   headers = {"X-Vault-Token": "hvs.wrapped_localhost_token"}
   ```
   - Plugin unwraps token via MockVaultProxy
   - Returns: `test_localhost_token_abcdef`
   - Caches in Redis: `vault:unwrapped:test-session-123:hvs.wrapped_localhost_token`
   - Transforms headers: removes `X-Vault-Token`, adds `Authorization: Bearer test_localhost_token_abcdef`

3. **Second Call** (same session):
   ```python
   headers = {"X-Vault-Token": "hvs.wrapped_localhost_token"}
   ```
   - Plugin checks Redis cache: **HIT** ✅
   - Returns cached token (no unwrap call)
   - Transforms headers same as first call

4. **Third Call** (same session):
   - Same as second call: **cache hit** ✅

### Expected Results

```
✅ First call: Token unwrapped and cached
   Unwrap call count: 1
✅ Second call: Used Redis cached token
   Unwrap call count: 1
✅ Third call: Redis cache still working
   Unwrap call count: 1

📊 Final stats:
   Total unwrap calls: 1
   Tokens unwrapped: 1
   Redis caching: ✅ Working
   Cache hits: 2 (second and third calls)
```

## Debugging

### Check Redis Cache

```bash
# Connect to Redis
docker exec -it mcp-context-forge-redis-1 redis-cli

# List all vault cache keys
KEYS vault:unwrapped:*

# Get specific cached token
GET vault:unwrapped:test-session-123:hvs.wrapped_localhost_token

# Check TTL (should be 3600 seconds = 1 hour)
TTL vault:unwrapped:test-session-123:hvs.wrapped_localhost_token

# Clear cache
FLUSHDB
```

### Common Issues

#### Redis Connection Failed

```bash
# Check if Redis is running
docker-compose ps redis

# Check Redis logs
docker-compose logs redis

# Restart Redis
docker-compose restart redis
```

#### Test Fails with "Token already unwrapped"

This means the wrapped token was used in a previous test run. Clear Redis cache:

```bash
docker exec -it mcp-context-forge-redis-1 redis-cli FLUSHDB
```

#### Environment Variables Not Set

Verify `pyproject.toml` has the pytest-env configuration. The test will fail if:
- `REDIS_URL` is not set
- `CACHE_TYPE` is not `redis`
- `PLUGINS_ENABLED` is not `true`

## Test Output Example

```
tests/e2e/test_vault_plugin_redis_only.py::test_vault_plugin_unwrap_and_cache 
🔧 Setting up test environment...
✅ Redis connection verified
✅ MockVaultProxy initialized with 1 wrapped tokens

📝 Test: Vault plugin unwrap and cache with Redis

🔑 First call with wrapped token...
   Session: test-session-123
   Wrapped token: hvs.wrapped_localhost_token
✅ First call successful
   Unwrapped token: test_localhost_token_abcdef
   Unwrap call count: 1
   Headers transformed: X-Vault-Token removed, Authorization added

🔑 Second call with same wrapped token (should use cache)...
✅ Second call successful
   Unwrapped token: test_localhost_token_abcdef
   Unwrap call count: 1 (no new unwrap - cache hit!)
   Headers transformed: X-Vault-Token removed, Authorization added

🔑 Third call with same wrapped token (should still use cache)...
✅ Third call successful
   Unwrapped token: test_localhost_token_abcdef
   Unwrap call count: 1 (no new unwrap - cache hit!)
   Headers transformed: X-Vault-Token removed, Authorization added

📊 Final verification:
   Total unwrap calls: 1
   Expected: 1
   ✅ Caching working correctly!

PASSED
```

## Architecture Notes

### Why Direct Plugin Call Instead of Full MCP Stack?

The simplified test architecture directly calls the vault plugin's `on_tool_call_request` hook instead of launching a full MCP Gateway + MCP Server stack. This provides:

1. **Speed**: Test runs in < 1 second vs 10+ seconds for full stack
2. **Reliability**: No process management, no timeouts, no SIGKILL issues
3. **Simplicity**: Easier to debug, clearer test flow
4. **Coverage**: Tests all vault plugin logic (unwrap, cache, transform)

The MCP protocol integration is tested elsewhere in the codebase. This test focuses on vault plugin functionality.

### MockVaultProxy Design

```python
class MockVaultProxy:
    def __init__(self):
        self.wrapped_tokens = {
            "hvs.wrapped_localhost_token": "test_localhost_token_abcdef"
        }
        self.unwrapped_tokens: set[str] = set()
        self.unwrap_call_count = 0

    async def unwrap_token(self, wrapped_token: str) -> str:
        if wrapped_token in self.unwrapped_tokens:
            raise ValueError(f"Token {wrapped_token} has already been unwrapped")
        
        if wrapped_token not in self.wrapped_tokens:
            raise ValueError(f"Unknown wrapped token: {wrapped_token}")
        
        self.unwrapped_tokens.add(wrapped_token)
        self.unwrap_call_count += 1
        return self.wrapped_tokens[wrapped_token]
```

Key features:
- Simulates HashiCorp Vault's single-use wrapped tokens
- Tracks unwrap call count for cache validation
- Raises errors for invalid/reused tokens

### Redis Caching Strategy

Cache key format: `vault:unwrapped:{session_id}:{wrapped_token}`

- **TTL**: 3600 seconds (1 hour)
- **Scope**: Per session (different sessions can unwrap same wrapped token)
- **Invalidation**: Automatic via TTL, or manual via `FLUSHDB`

## Related Tests

- **Functional tests**: `tests/functional/test_vault_plugin_functional.py`
  - Tests vault plugin with FastAPI test client
  - No external dependencies
  - Validates HTTP request/response flow

## Contributing

When modifying the vault plugin or this test:

1. Ensure Redis is running: `docker-compose up -d redis`
2. Run the test: `pytest tests/e2e/test_vault_plugin_redis_only.py -v -s`
3. Verify cache behavior: Check Redis keys and TTL
4. Update this README if test flow changes

## References

- Vault Plugin: `plugins/vault/__init__.py`
- Plugin Framework: `mcpgateway/plugins/framework/`
- Redis Cache: `mcpgateway/cache/redis_cache.py`
- HashiCorp Vault Docs: https://developer.hashicorp.com/vault/docs/concepts/response-wrapping