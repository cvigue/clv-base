# Copyright (c) 2023- Charlie Vigue. All rights reserved.

#!/bin/bash
# NetCore Server Integration Tests (includes HTTP integration tests)
# Tests the simple_server with real HTTP requests

# Note: Don't use 'set -e' - we want to continue running tests even if some fail

# Colors for output - only use colors if output is to a terminal
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    # No colors when output is redirected/captured
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Configuration
SERVER_PORT=8443
SERVER_URL="https://localhost:${SERVER_PORT}"
CURL_OPTS="-k -s --max-time 5"

# Support both CMake-launched (SERVER_BINARY env var) and manual execution
if [ -n "$SERVER_BINARY" ]; then
    SERVER_BIN="$SERVER_BINARY"
else
    # Default: look for binary in current directory (when run from build directory)
    # or in ../build/NetCore (when run from source directory)
    if [ -f "./simple_server" ]; then
        SERVER_BIN="./simple_server"
    else
        BUILD_DIR="${BUILD_DIR:-../build/NetCore}"
        SERVER_BIN="${BUILD_DIR}/simple_server"
    fi
fi

# Test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo -e "\n${YELLOW}Shutting down test server (PID: $SERVER_PID)...${NC}"
        kill -INT "$SERVER_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Test helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo -e "  ${RED}Error: $2${NC}"
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
}

test_endpoint() {
    local name="$1"
    local method="$2"
    local path="$3"
    local expected_code="$4"
    shift 4
    local extra_args=("$@")

    if [ "$method" = "GET" ]; then
        response=$(curl $CURL_OPTS -w "\n%{http_code}" "${extra_args[@]}" "${SERVER_URL}${path}" 2>&1)
    else
        response=$(curl $CURL_OPTS -w "\n%{http_code}" -X "$method" "${extra_args[@]}" "${SERVER_URL}${path}" 2>&1)
    fi

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)

    if [ "$http_code" = "$expected_code" ]; then
        pass "$name (HTTP $http_code)"
        echo "$body"
    else
        fail "$name" "Expected HTTP $expected_code, got $http_code"
    fi
}

test_response_contains() {
    local name="$1"
    local method="$2"
    local path="$3"
    local expected_text="$4"
    shift 4
    local extra_args=("$@")

    if [ "$method" = "GET" ]; then
        response=$(curl $CURL_OPTS "${extra_args[@]}" "${SERVER_URL}${path}" 2>&1)
    else
        response=$(curl $CURL_OPTS -X "$method" "${extra_args[@]}" "${SERVER_URL}${path}" 2>&1)
    fi

    # Use grep -F for literal string matching (handles special chars and whitespace better)
    if echo "$response" | grep -qF "$expected_text"; then
        pass "$name"
    else
        fail "$name" "Response doesn't contain '$expected_text'"
        echo "  Got: $(echo "$response" | head -c 200)..." # Truncate long responses
    fi
}

# Main script
echo "=========================================="
echo "NetCore Server Integration Tests (HTTP integration)"
echo "=========================================="
echo ""

# Check if server binary exists
if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}Error: Server binary not found at $SERVER_BIN${NC}"
    echo "Build the server first: cmake --build . --target simple_server"
    exit 1
fi

# Start the server
echo -e "${YELLOW}Starting test server on port $SERVER_PORT...${NC}"
cd "$BUILD_DIR"
./simple_server > /tmp/test_server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to initialize..."
sleep 2

# Verify server is running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo -e "${RED}Error: Server failed to start${NC}"
    cat /tmp/test_server.log
    exit 1
fi

echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"
echo ""

# Run tests
echo "=========================================="
echo "Running Tests"
echo "=========================================="
echo ""

# Test 1: API Hello endpoint
echo "Test 1: API Hello Endpoint"
test_response_contains "GET /api/hello" "GET" "/api/hello" "Hello from Simple Server!"
echo ""

# Test 2: API 404 handling
echo "Test 2: API 404 Handling"
test_endpoint "GET /api/unknown" "GET" "/api/unknown" "404"
test_response_contains "API error message" "GET" "/api/unknown" "not found"
echo ""

# Test 3: Static file serving (index.html)
echo "Test 3: Homepage (Static Files)"
test_endpoint "GET /" "GET" "/" "200"
test_response_contains "Homepage content" "GET" "/" "Simple Server"
echo ""

# Test 4: 404 handling for nonexistent static files
echo "Test 4: 404 Error Handling"
test_endpoint "GET /nonexistent" "GET" "/nonexistent" "404"
echo ""

# Test 5: Keep-alive (multiple requests on same connection)
echo "Test 5: Keep-Alive Support"
# This tests that the connection stays open for multiple requests
response=$(curl $CURL_OPTS "${SERVER_URL}/api/hello" "${SERVER_URL}/" 2>&1)
if echo "$response" | grep -q "Hello from Simple Server" && echo "$response" | grep -q "Simple Server"; then
    pass "Multiple requests on same connection"
else
    fail "Keep-alive test" "Failed to complete multiple requests"
fi
echo ""

# Test 6: Concurrent Requests
echo "Test 6: Concurrent Requests"
echo "Sending 5 parallel requests..."
for i in {1..5}; do
    (timeout 10 curl $CURL_OPTS "${SERVER_URL}/api/hello") > /tmp/test_concurrent_${i}.txt 2>&1 &
done

# Give the requests time to complete (up to 12 seconds)
# Use a simple counter instead of wait to avoid blocking forever
for attempt in {1..12}; do
    active_jobs=$(jobs -p | wc -l)
    if [ "$active_jobs" -eq 0 ]; then
        break
    fi
    sleep 1
done

# Kill any remaining background jobs if they're still running (excluding the server)
jobs -p | grep -v "^$SERVER_PID$" | xargs -r kill -9 2>/dev/null

success_count=$(grep -l "Hello from Simple Server" /tmp/test_concurrent_*.txt 2>/dev/null | wc -l)
rm -f /tmp/test_concurrent_*.txt
if [ "$success_count" -eq 5 ]; then
    pass "Concurrent requests (5/5 succeeded)"
else
    fail "Concurrent requests" "Only $success_count/5 requests succeeded"
fi
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total tests run: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
else
    echo "Failed: 0"
fi
echo ""

# Check server log for errors
echo "Checking server log for errors..."
if grep -i "error\|exception\|failed" /tmp/test_server.log > /dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Errors found in server log:${NC}"
    grep -i "error\|exception\|failed" /tmp/test_server.log | head -5
else
    echo -e "${GREEN}No errors in server log${NC}"
fi
echo ""

# Exit with appropriate code
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
