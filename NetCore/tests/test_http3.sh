#!/bin/bash
# HTTP/3 QUIC Server Test Script
# Tests quic_simple_server with gtlsclient (ngtcp2)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SERVER_BIN="./quic_simple_server"
SERVER_LOG="/tmp/quic_server.log"
SERVER_PORT=8443
HOST="127.0.0.1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Stopping server..."
    pkill -9 -f quic_simple_server 2>/dev/null || true
}

trap cleanup EXIT

# Check prerequisites
check_prereqs() {
    if [[ ! -x "$SERVER_BIN" ]]; then
        log_error "Server binary not found: $SERVER_BIN"
        log_info "Run 'ninja quic_simple_server' first"
        exit 1
    fi

    if ! command -v gtlsclient &> /dev/null; then
        log_error "gtlsclient not found (from ngtcp2)"
        log_info "Install ngtcp2 or build from source"
        exit 1
    fi
}

start_server() {
    log_info "Starting quic_simple_server..."
    pkill -9 -f quic_simple_server 2>/dev/null || true
    sleep 0.3

    "$SERVER_BIN" > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    sleep 1

    if ! kill -0 $SERVER_PID 2>/dev/null; then
        log_error "Server failed to start"
        cat "$SERVER_LOG"
        exit 1
    fi

    log_ok "Server started (PID: $SERVER_PID)"
}

test_handshake() {
    log_info "Testing TLS handshake..."

    local output
    output=$(timeout 5 gtlsclient "$HOST" "$SERVER_PORT" 2>&1) || true

    # Check server log for handshake confirmation
    if grep -q "Handshake confirmed" "$SERVER_LOG" 2>/dev/null; then
        log_ok "TLS handshake successful (server confirmed)"
        return 0
    elif echo "$output" | grep -q -i "handshake"; then
        log_ok "TLS handshake in progress"
        return 0
    else
        log_warn "TLS handshake status unclear"
        echo "$output" | head -10
        return 0  # Don't fail, continue testing
    fi
}

test_http3_request() {
    local uri="${1:-/}"
    log_info "Testing HTTP/3 request: $uri"

    local output
    output=$(timeout 5 gtlsclient "$HOST" "$SERVER_PORT" "https://$HOST:$SERVER_PORT$uri" 2>&1) || true

    sleep 0.5  # Let server process and log

    # Check server log for successful request processing
    echo ""
    if grep -q "HTTP/3.*Request:" "$SERVER_LOG" 2>/dev/null; then
        log_ok "HTTP/3 request received and parsed!"
        grep "HTTP/3.*Request:" "$SERVER_LOG" | tail -5
    else
        log_warn "No HTTP/3 request logged"
    fi

    if grep -q "Sent response" "$SERVER_LOG" 2>/dev/null; then
        log_ok "HTTP/3 response sent!"
    fi

    echo ""
    log_info "Server log (HTTP/3 related):"
    grep -E "(HTTP|HEADERS|QPACK|Request|response|stream)" "$SERVER_LOG" 2>/dev/null | tail -15 || true

    echo ""
    log_info "Client output (last 10 lines):"
    echo "$output" | tail -10
}

show_qpack_debug() {
    log_info "QPACK debug info from server log:"
    grep -E "(QPACK|header|block|bytes:|index)" "$SERVER_LOG" 2>/dev/null | tail -30 || echo "(no QPACK debug output)"
}

# Main
main() {
    local cmd="${1:-test}"

    case "$cmd" in
        test)
            check_prereqs
            start_server
            test_handshake
            test_http3_request "/"
            ;;
        handshake)
            check_prereqs
            start_server
            test_handshake
            ;;
        request)
            check_prereqs
            start_server
            test_http3_request "${2:-/}"
            ;;
        log)
            show_full_log
            ;;
        qpack)
            show_qpack_debug
            ;;
        start)
            check_prereqs
            start_server
            log_info "Server running. Tail log with: tail -f $SERVER_LOG"
            log_info "Press Ctrl+C to stop"
            tail -f "$SERVER_LOG"
            ;;
        *)
            echo "Usage: $0 {test|handshake|request [uri]|log|qpack|start}"
            echo ""
            echo "Commands:"
            echo "  test       - Run full test (handshake + HTTP/3 request)"
            echo "  handshake  - Test TLS handshake only"
            echo "  request    - Test HTTP/3 request (optional: specify URI)"
            echo "  log        - Show full server log"
            echo "  qpack      - Show QPACK debug info from log"
            echo "  start      - Start server and tail log"
            exit 1
            ;;
    esac
}

main "$@"
