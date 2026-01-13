# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/plugins/vault/test_vault_plugin_performance.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Adrian Popa

Performance tests for Vault Plugin - measures overhead and scalability.

Run with:
    uv run pytest tests/unit/mcpgateway/plugins/plugins/vault/test_vault_plugin_performance.py -v -s
"""

# Standard
import json
import time
from statistics import mean, median

# Third-Party
import pytest

# First-Party
from mcpgateway.plugins.framework import (
    GlobalContext,
    HttpHeaderPayload,
    PluginConfig,
    PluginContext,
    PluginMode,
    ToolHookType,
    ToolPreInvokePayload,
)

# Import the Vault plugin
from plugins.vault.vault_plugin import Vault


class TestVaultPluginPerformance:
    """Performance tests for Vault plugin."""

    @pytest.fixture
    def plugin_config(self) -> PluginConfig:
        """Create a test plugin configuration."""
        return PluginConfig(
            name="TestVault",
            description="Test Vault Plugin",
            author="Test",
            kind="plugins.vault.vault_plugin.Vault",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test", "vault"],
            mode=PluginMode.ENFORCE,
            priority=10,
            config={
                "system_tag_prefix": "system",
                "vault_header_name": "X-Vault-Tokens",
                "vault_handling": "raw",
                "system_handling": "tag",
                "auth_header_tag_prefix": "AUTH_HEADER",
            },
        )

    @pytest.fixture
    def plugin_context(self) -> PluginContext:
        """Create a test plugin context with gateway metadata."""
        gateway_metadata = type("obj", (object,), {"tags": [{"id": "1", "label": "system:github.com"}, {"id": "2", "label": "AUTH_HEADER:X-GitHub-Token"}]})()

        global_context = GlobalContext(request_id="test-perf", metadata={"gateway": gateway_metadata})

        return PluginContext(global_context=global_context)

    @pytest.fixture
    def plugin_context_no_auth_header(self) -> PluginContext:
        """Create a test plugin context without AUTH_HEADER tag."""
        gateway_metadata = type("obj", (object,), {"tags": [{"id": "1", "label": "system:github.com"}]})()

        global_context = GlobalContext(request_id="test-perf", metadata={"gateway": gateway_metadata})

        return PluginContext(global_context=global_context)

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_plugin_overhead_no_vault_header(self, plugin_config, plugin_context):
        """Measure overhead when no vault header is present (fast path)."""
        plugin = Vault(plugin_config)

        # Create payload without vault header
        payload = ToolPreInvokePayload(name="test_tool", headers=HttpHeaderPayload(root={"Content-Type": "application/json"}))

        # Warmup
        for _ in range(10):
            await plugin.tool_pre_invoke(payload, plugin_context)

        # Measure
        iterations = 1000
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            await plugin.tool_pre_invoke(payload, plugin_context)
            end = time.perf_counter()
            times.append((end - start) * 1000)

        mean_ms = mean(times)
        median_ms = median(times)
        p95_ms = sorted(times)[int(len(times) * 0.95)]
        p99_ms = sorted(times)[int(len(times) * 0.99)]

        print(f"\n{'=' * 70}")
        print("Performance: No Vault Header (Fast Path)")
        print(f"{'=' * 70}")
        print(f"Iterations: {iterations}")
        print(f"Mean:       {mean_ms:.4f}ms")
        print(f"Median:     {median_ms:.4f}ms")
        print(f"P95:        {p95_ms:.4f}ms")
        print(f"P99:        {p99_ms:.4f}ms")
        print(f"Min:        {min(times):.4f}ms")
        print(f"Max:        {max(times):.4f}ms")
        print(f"{'=' * 70}\n")

        # Assert reasonable performance (should be very fast)
        assert mean_ms < 1.0, f"Fast path too slow: {mean_ms:.4f}ms"
        assert p99_ms < 2.0, f"P99 too slow: {p99_ms:.4f}ms"

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_plugin_overhead_simple_token(self, plugin_config, plugin_context_no_auth_header):
        """Measure overhead with simple token processing (OAuth2)."""
        plugin = Vault(plugin_config)

        # Create vault tokens with simple key
        vault_tokens = {"github.com": "ghp_test123456789"}
        payload = ToolPreInvokePayload(name="test_tool", headers=HttpHeaderPayload(root={"Content-Type": "application/json", "X-Vault-Tokens": json.dumps(vault_tokens)}))

        # Warmup
        for _ in range(10):
            await plugin.tool_pre_invoke(payload, plugin_context_no_auth_header)

        # Measure
        iterations = 1000
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            await plugin.tool_pre_invoke(payload, plugin_context_no_auth_header)
            end = time.perf_counter()
            times.append((end - start) * 1000)

        mean_ms = mean(times)
        p95_ms = sorted(times)[int(len(times) * 0.95)]
        p99_ms = sorted(times)[int(len(times) * 0.99)]

        print(f"\n{'=' * 70}")
        print("Performance: Simple Token (OAuth2)")
        print(f"{'=' * 70}")
        print(f"Iterations: {iterations}")
        print(f"Mean:       {mean_ms:.4f}ms")
        print(f"Median:     {median(times):.4f}ms")
        print(f"P95:        {p95_ms:.4f}ms")
        print(f"P99:        {p99_ms:.4f}ms")
        print(f"{'=' * 70}\n")

        # Assert reasonable performance
        assert mean_ms < 2.0, f"Simple token processing too slow: {mean_ms:.4f}ms"
        assert p99_ms < 5.0, f"P99 too slow: {p99_ms:.4f}ms"

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_plugin_overhead_complex_token(self, plugin_config, plugin_context):
        """Measure overhead with complex token key parsing (PAT with AUTH_HEADER)."""
        plugin = Vault(plugin_config)

        # Create vault tokens with complex key
        vault_tokens = {"github.com:USER:PAT:TOKEN": "ghp_pat_token123"}
        payload = ToolPreInvokePayload(name="test_tool", headers=HttpHeaderPayload(root={"Content-Type": "application/json", "X-Vault-Tokens": json.dumps(vault_tokens)}))

        # Warmup
        for _ in range(10):
            await plugin.tool_pre_invoke(payload, plugin_context)

        # Measure
        iterations = 1000
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            await plugin.tool_pre_invoke(payload, plugin_context)
            end = time.perf_counter()
            times.append((end - start) * 1000)

        mean_ms = mean(times)
        p95_ms = sorted(times)[int(len(times) * 0.95)]
        p99_ms = sorted(times)[int(len(times) * 0.99)]

        print(f"\n{'=' * 70}")
        print("Performance: Complex Token (PAT with AUTH_HEADER)")
        print(f"{'=' * 70}")
        print(f"Iterations: {iterations}")
        print(f"Mean:       {mean_ms:.4f}ms")
        print(f"P95:        {p95_ms:.4f}ms")
        print(f"P99:        {p99_ms:.4f}ms")
        print(f"{'=' * 70}\n")

        # Assert reasonable performance
        assert mean_ms < 2.0, f"Complex token processing too slow: {mean_ms:.4f}ms"
        assert p99_ms < 5.0, f"P99 too slow: {p99_ms:.4f}ms"

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_plugin_scalability_large_vault(self, plugin_config, plugin_context):
        """Test scalability with large number of tokens in vault."""
        plugin = Vault(plugin_config)

        # Test with different vault sizes
        sizes = [1, 5, 10, 25, 50]
        results = {}

        for size in sizes:
            vault_tokens = {f"system{i}.com": f"token_{i}" for i in range(size)}
            vault_tokens["github.com:USER:PAT:TOKEN"] = "ghp_target_token"

            payload = ToolPreInvokePayload(name="test_tool", headers=HttpHeaderPayload(root={"X-Vault-Tokens": json.dumps(vault_tokens)}))

            # Warmup
            for _ in range(5):
                await plugin.tool_pre_invoke(payload, plugin_context)

            # Measure
            iterations = 200
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                await plugin.tool_pre_invoke(payload, plugin_context)
                end = time.perf_counter()
                times.append((end - start) * 1000)

            results[size] = {"mean_ms": mean(times), "p95_ms": sorted(times)[int(len(times) * 0.95)], "p99_ms": sorted(times)[int(len(times) * 0.99)]}

        print(f"\n{'=' * 70}")
        print("Performance: Scalability by Vault Size")
        print(f"{'=' * 70}")
        print(f"{'Size':<6} {'Mean (ms)':<12} {'P95 (ms)':<12} {'P99 (ms)':<12}")
        print(f"{'-' * 70}")
        for size, stats in results.items():
            print(f"{size:<6} {stats['mean_ms']:<12.4f} {stats['p95_ms']:<12.4f} {stats['p99_ms']:<12.4f}")
        print(f"{'=' * 70}\n")

        # Verify linear or sub-linear scaling
        mean_1 = results[1]["mean_ms"]
        mean_50 = results[50]["mean_ms"]
        scaling_factor = mean_50 / mean_1

        print(f"Scaling factor (50x tokens): {scaling_factor:.2f}x slower")
        assert scaling_factor < 10, f"Poor scaling: {scaling_factor:.2f}x slower with 50x tokens"
        assert mean_50 < 10.0, f"Large vault too slow: {mean_50:.4f}ms"

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_plugin_throughput(self, plugin_config, plugin_context):
        """Measure plugin throughput (requests per second)."""
        plugin = Vault(plugin_config)

        vault_tokens = {"github.com": "ghp_token123"}
        payload = ToolPreInvokePayload(name="test_tool", headers=HttpHeaderPayload(root={"X-Vault-Tokens": json.dumps(vault_tokens)}))

        # Warmup
        for _ in range(10):
            await plugin.tool_pre_invoke(payload, plugin_context)

        # Measure throughput over 1 second
        iterations = 0
        start_time = time.perf_counter()
        duration = 1.0  # 1 second

        while (time.perf_counter() - start_time) < duration:
            await plugin.tool_pre_invoke(payload, plugin_context)
            iterations += 1

        elapsed = time.perf_counter() - start_time
        throughput = iterations / elapsed

        print(f"\n{'=' * 70}")
        print("Throughput Test")
        print(f"{'=' * 70}")
        print(f"Duration:    {elapsed:.2f}s")
        print(f"Iterations:  {iterations}")
        print(f"Throughput:  {throughput:.2f} req/s")
        print(f"Latency:     {1000/throughput:.4f}ms per request")
        print(f"{'=' * 70}\n")

        # Assert reasonable throughput (should handle thousands per second)
        assert throughput > 500, f"Throughput too low: {throughput:.2f} req/s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

# Made with Bob
