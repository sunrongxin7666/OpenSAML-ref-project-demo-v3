#!/usr/bin/env bash
#
# SAML SSO End-to-End Regression Test
#
# Tests the complete SAML SSO flow between SP (port 8080) and IDP (port 9090):
#   User → SP protected resource → redirect to IDP → login → artifact redirect
#   → SP consumer (SOAP artifact resolution) → session → protected resource
#
# Usage: ./regression-test.sh
# Exit code: 0 = all tests passed, 1 = one or more tests failed

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
IDP_PORT=9090
SP_PORT=8080
IDP_LOG="$PROJECT_DIR/idp.log"
SP_LOG="$PROJECT_DIR/sp.log"
COOKIE_JAR="$PROJECT_DIR/.test-cookies"
HEALTH_TIMEOUT=60  # seconds

PASSED=0
FAILED=0
TOTAL=0

# --- Color output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# --- Cleanup on exit ---
IDP_PID=""
SP_PID=""

cleanup() {
    info "Cleaning up..."
    [ -n "$SP_PID" ]  && kill "$SP_PID"  2>/dev/null && wait "$SP_PID" 2>/dev/null || true
    [ -n "$IDP_PID" ] && kill "$IDP_PID" 2>/dev/null && wait "$IDP_PID" 2>/dev/null || true
    rm -f "$COOKIE_JAR" "$IDP_LOG" "$SP_LOG"
    info "Cleanup done."
}
trap cleanup EXIT

# --- Assert helpers ---
assert_contains() {
    local label="$1" body="$2" expected="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$body" | grep -qF "$expected"; then
        pass "$label"
        PASSED=$((PASSED + 1))
    else
        fail "$label (expected body to contain: '$expected')"
        FAILED=$((FAILED + 1))
    fi
}

assert_http_code() {
    local label="$1" actual="$2" expected="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" = "$expected" ]; then
        pass "$label"
        PASSED=$((PASSED + 1))
    else
        fail "$label (expected HTTP $expected, got HTTP $actual)"
        FAILED=$((FAILED + 1))
    fi
}

assert_header_contains() {
    local label="$1" headers="$2" expected="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$headers" | grep -qiF "$expected"; then
        pass "$label"
        PASSED=$((PASSED + 1))
    else
        fail "$label (expected header to contain: '$expected')"
        FAILED=$((FAILED + 1))
    fi
}

# ============================================================
# Step 1: Build
# ============================================================
info "Building project..."
cd "$PROJECT_DIR"
# Use custom truststore if available (for JDK 8 with outdated CA certs)
if [ -f /tmp/cacerts-custom ]; then
    export MAVEN_OPTS="-Djavax.net.ssl.trustStore=/tmp/cacerts-custom -Djavax.net.ssl.trustStorePassword=changeit"
fi
mvn clean package -DskipTests -q
info "Build complete."

# ============================================================
# Step 2: Start IDP and SP
# ============================================================
info "Starting IDP on port $IDP_PORT..."
java -jar "$PROJECT_DIR/saml-idp/target/saml-idp-1.0-SNAPSHOT.jar" > "$IDP_LOG" 2>&1 &
IDP_PID=$!

info "Starting SP on port $SP_PORT..."
java -jar "$PROJECT_DIR/saml-sp/target/saml-sp-1.0-SNAPSHOT.jar" > "$SP_LOG" 2>&1 &
SP_PID=$!

# ============================================================
# Step 3: Health check - wait for both services
# ============================================================
wait_for_port() {
    local label="$1" port="$2" pid="$3"
    local elapsed=0
    info "Waiting for $label (port $port)..."
    while [ $elapsed -lt $HEALTH_TIMEOUT ]; do
        # Check process is still alive
        if ! kill -0 "$pid" 2>/dev/null; then
            fail "$label process died during startup. Check log."
            cat "$4" | tail -30
            exit 1
        fi
        if curl -s -o /dev/null -w '' "http://localhost:$port" 2>/dev/null; then
            info "$label is ready. (${elapsed}s)"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    fail "$label did not become ready within ${HEALTH_TIMEOUT}s"
    exit 1
}

wait_for_port "IDP" "$IDP_PORT" "$IDP_PID" "$IDP_LOG"
wait_for_port "SP"  "$SP_PORT"  "$SP_PID"  "$SP_LOG"

echo ""
info "=============================="
info "  Running Test Cases"
info "=============================="
echo ""

# ============================================================
# TC1: Access SP protected resource → redirect to IDP
# ============================================================
info "TC1: Access SP protected resource, expect redirect to IDP"
RESP_HEADERS=$(curl -s -D - -o /dev/null "http://localhost:$SP_PORT/app/appservlet")
HTTP_CODE=$(echo "$RESP_HEADERS" | head -1 | grep -oE '[0-9]{3}')

assert_http_code "TC1a: SP returns 302 redirect" "$HTTP_CODE" "302"
assert_header_contains "TC1b: Redirect Location contains IDP SSO URL" "$RESP_HEADERS" "localhost:$IDP_PORT/idp/singleSignOnService"
assert_header_contains "TC1c: Redirect carries SAMLRequest parameter" "$RESP_HEADERS" "SAMLRequest="

# ============================================================
# TC2: Access IDP SSO endpoint → login page
# ============================================================
info "TC2: Access IDP SSO endpoint, expect login page"
LOGIN_BODY=$(curl -s "http://localhost:$IDP_PORT/idp/singleSignOnService")

assert_contains "TC2a: IDP returns login page with form" "$LOGIN_BODY" "<form"
assert_contains "TC2b: Login page contains Authenticate button" "$LOGIN_BODY" "Authenticate"

# ============================================================
# TC3: POST login form → redirect to SP consumer with SAMLart
# ============================================================
info "TC3: POST login form, expect redirect to SP consumer with SAMLart"
# First, get the redirect URL from SP to use as the IDP landing (with SAMLRequest)
REDIRECT_URL=$(curl -s -D - -o /dev/null "http://localhost:$SP_PORT/app/appservlet" \
    | grep -i '^location:' | sed 's/[Ll]ocation: *//' | tr -d '\r\n')

# POST to the IDP SSO endpoint (same URL) to authenticate
POST_HEADERS=$(curl -s -D - -o /dev/null -X POST "http://localhost:$IDP_PORT/idp/singleSignOnService")
POST_CODE=$(echo "$POST_HEADERS" | head -1 | grep -oE '[0-9]{3}')

assert_http_code "TC3a: IDP POST returns 302 redirect" "$POST_CODE" "302"
POST_LOCATION=$(echo "$POST_HEADERS" | grep -i '^location:' | sed 's/[Ll]ocation: *//' | tr -d '\r\n')
assert_contains "TC3b: Redirect to SP consumer endpoint" "$POST_LOCATION" "localhost:$SP_PORT/sp/consumer"
assert_contains "TC3c: Redirect carries SAMLart parameter" "$POST_LOCATION" "SAMLart="

# ============================================================
# TC4: Full SSO flow with cookies & redirects
# ============================================================
info "TC4: Full SSO flow (cookie jar + follow redirects)"
rm -f "$COOKIE_JAR"

# Step 4a: Hit the protected resource, follow redirect to IDP
curl -s -L -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -o /dev/null -D - \
    --max-redirs 1 \
    "http://localhost:$SP_PORT/app/appservlet" > /dev/null 2>&1

# Step 4b: POST to IDP to authenticate, capture redirect to SP consumer
IDP_REDIRECT=$(curl -s -D - -o /dev/null \
    -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -X POST "http://localhost:$IDP_PORT/idp/singleSignOnService" \
    | grep -i '^location:' | sed 's/[Ll]ocation: *//' | tr -d '\r\n')

# Step 4c: Follow the artifact redirect to SP consumer (which does SOAP resolution + redirects to resource)
FINAL_BODY=$(curl -s -L -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$IDP_REDIRECT")

assert_contains "TC4: Full SSO flow returns protected resource" "$FINAL_BODY" "You are now at the requested resource"

# ============================================================
# TC5: Authenticated session - direct access to protected resource
# ============================================================
info "TC5: Verify session persists, access protected resource directly"
SESSION_BODY=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "http://localhost:$SP_PORT/app/appservlet")

assert_contains "TC5: Session access returns protected resource" "$SESSION_BODY" "You are now at the requested resource"

# ============================================================
# Results Summary
# ============================================================
echo ""
info "=============================="
info "  Test Results"
info "=============================="
echo ""
pass "Passed: $PASSED"
[ "$FAILED" -gt 0 ] && fail "Failed: $FAILED" || info "Failed: $FAILED"
info "Total:  $TOTAL"
echo ""

if [ "$FAILED" -gt 0 ]; then
    fail "REGRESSION TEST FAILED"
    exit 1
else
    pass "ALL TESTS PASSED"
    exit 0
fi
