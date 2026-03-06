#!/bin/bash
# -*- coding: utf-8 -*-
# Location: ./tests/e2e/setup_vault_test.sh
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Adrian Popa
#
# Setup script for Vault Plugin E2E tests
# This script ensures Redis is running and environment is configured

set -e

echo "🔧 Setting up Vault Plugin E2E Test Environment"
echo ""

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Please install docker-compose."
    exit 1
fi

# Start Redis if not running
echo "📦 Checking Redis status..."
if docker-compose ps redis | grep -q "Up"; then
    echo "✅ Redis is already running"
else
    echo "🚀 Starting Redis..."
    docker-compose up -d redis
    
    # Wait for Redis to be ready
    echo "⏳ Waiting for Redis to be ready..."
    for i in {1..30}; do
        if docker-compose exec -T redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
            echo "✅ Redis is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "❌ Redis failed to start after 30 seconds"
            exit 1
        fi
        sleep 1
    done
fi

# Verify Redis connection
echo ""
echo "🔍 Verifying Redis connection..."
if docker-compose exec -T redis redis-cli ping | grep -q "PONG"; then
    echo "✅ Redis connection verified"
else
    echo "❌ Cannot connect to Redis"
    exit 1
fi

# Set environment variables
echo ""
echo "🔧 Setting environment variables..."
export REDIS_URL=redis://localhost:6379/0
export VAULT_PROXY_URL=http://mock-vault:8200
export VAULT_API_KEY=test-vault-api-key-12345
export PLUGINS_ENABLED=true
export REQUIRE_TOKEN_EXPIRATION=false
export LOG_LEVEL=INFO

echo "✅ Environment configured:"
echo "   REDIS_URL=$REDIS_URL"
echo "   VAULT_PROXY_URL=$VAULT_PROXY_URL"
echo "   PLUGINS_ENABLED=$PLUGINS_ENABLED"

echo ""
echo "✅ Setup complete! Ready to run tests."
echo ""
echo "Run tests with:"
echo "  pytest tests/e2e/test_vault_plugin_redis_only.py -v -s"

# Made with Bob
