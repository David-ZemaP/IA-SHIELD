#!/bin/bash
# Run IA-Seguridad phishing detection tests

echo "🚀 IA-SEGURIDAD - Running Phishing Detection Tests"
echo ""

# Build the test container
echo "📦 Building test container..."
docker build -f Dockerfile.test -t ia-seguridad-test .

# Run the test container (connects to localhost:8000)
echo ""
echo "🧪 Running tests..."
docker run --rm --network host ia-seguridad-test