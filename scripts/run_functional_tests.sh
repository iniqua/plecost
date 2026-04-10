#!/usr/bin/env bash
set -e

echo "Starting WordPress test environment..."
docker-compose -f docker-compose.test.yml up -d

echo "Waiting for WordPress to be ready..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8765/wp-login.php > /dev/null 2>&1; then
        echo "WordPress is ready!"
        break
    fi
    echo "Attempt $i/30..."
    sleep 5
done

echo "Running functional tests..."
PLECOST_FUNCTIONAL_TESTS=1 python3 -m pytest tests/functional/ -v --tb=short

echo "Stopping test environment..."
docker-compose -f docker-compose.test.yml down
