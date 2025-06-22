#!/bin/bash

# OpenID Connect Vue.js Demo Startup Script
set -e

echo "🚀 Starting OpenID Connect Vue.js Demo..."
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker compose > /dev/null 2>&1; then
    echo "❌ Docker Compose is not available. Please install Docker Compose and try again."
    exit 1
fi

# Build and start services
echo "🔨 Building and starting services..."
docker compose up --build -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."
sleep 5

# Check service health
echo "🔍 Checking service health..."

# Check OIDC provider
if curl -s http://localhost:18888/health > /dev/null; then
    echo "✅ OIDC Provider is healthy"
else
    echo "❌ OIDC Provider is not responding"
    docker compose logs oidcld
    exit 1
fi

# Check Vue.js app (may take a moment to start)
echo "⏳ Waiting for Vue.js application to start..."
for i in {1..30}; do
    if curl -s http://localhost:5173 > /dev/null; then
        echo "✅ Vue.js Application is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Vue.js Application failed to start"
        docker compose logs vue-app
        exit 1
    fi
    sleep 2
done

echo ""
echo "🎉 Demo is ready!"
echo ""
echo "📱 Vue.js Application: http://localhost:5173"
echo "🔐 OIDC Provider: http://localhost:18888"
echo "🔍 OIDC Discovery: http://localhost:18888/.well-known/openid-configuration"
echo ""
echo "👥 Demo Users:"
echo "   • demo-admin (Administrator)"
echo "   • demo-user (Regular User)"
echo "   • test-developer (Developer)"
echo "   • guest-user (Guest)"
echo ""
echo "📋 Useful Commands:"
echo "   • View logs: docker compose logs -f"
echo "   • Stop demo: docker compose down"
echo "   • Restart: docker compose restart"
echo ""
echo "🌐 Open http://localhost:5173 in your browser to start testing!"

# Optionally open browser (uncomment if desired)
# if command -v open > /dev/null 2>&1; then
#     open http://localhost:5173
# elif command -v xdg-open > /dev/null 2>&1; then
#     xdg-open http://localhost:5173
# fi
