#!/usr/bin/env bash
set -eo pipefail

echo "================================================================"
echo "    CLOAK COMPREHENSIVE END-TO-END VERIFICATION SUITE"
echo "================================================================"

PASSED=0
FAILED=0

assert_eq() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  [PASS] $name"
        PASSED=$((PASSED + 1))
    else
        echo "  [FAIL] $name"
        echo "    Expected: '$expected'"
        echo "    Actual:   '$actual'"
        FAILED=$((FAILED + 1))
    fi
}

assert_contains() {
    local name="$1"
    local needle="$2"
    local haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "  [PASS] $name"
        PASSED=$((PASSED + 1))
    else
        echo "  [FAIL] $name"
        echo "    Expected to contain: '$needle'"
        echo "    Haystack:            '$haystack'"
        FAILED=$((FAILED + 1))
    fi
}

echo ""
echo ">>> [1/7] Testing CLI Basic Commands & Binary Integrity..."
VERSION_OUT=$(cloak --version)
assert_contains "CLI Version Check" "cloak 0.6.0" "$VERSION_OUT"

HELP_OUT=$(cloak --help)
assert_contains "Help includes proxy subcommand" "proxy" "$HELP_OUT"
assert_contains "Help includes gui subcommand" "gui" "$HELP_OUT"
assert_contains "Help includes init subcommand" "init" "$HELP_OUT"
assert_contains "Help includes setup subcommand" "setup" "$HELP_OUT"

echo ""
echo ">>> [2/7] Testing Global Secrets Storage & Masking (macOS Keychain)..."
cloak set -g E2E_GLOBAL_KEY "sk-super-secret-global-998877"
LIST_OUT=$(cloak list -g)
assert_contains "Global Secret in list" "E2E_GLOBAL_KEY" "$LIST_OUT"

GET_MASKED=$(cloak get -g E2E_GLOBAL_KEY)
assert_contains "Get masked displays bullet mask" "sk-s••••••••8877" "$GET_MASKED"

GET_REVEAL=$(cloak get -g E2E_GLOBAL_KEY --reveal)
assert_eq "Get --reveal shows raw value" "sk-super-secret-global-998877" "$GET_REVEAL"

NO_PROMPT_STATUS=$(cloak get -g NON_EXISTENT_KEY_XYZ --no-prompt >/dev/null 2>&1 && echo "0" || echo "1")
assert_eq "Get missing secret with --no-prompt exits with error" "1" "$NO_PROMPT_STATUS"

CA_PATH=$(cloak ca path)
assert_contains "CA path returns valid ca.pem" "ca.pem" "$CA_PATH"

echo ""
echo ">>> [3/7] Testing Project Scoping, Inheritance & Overriding..."
TEMP_PROJ="/tmp/cloak_e2e_project_$$"
mkdir -p "$TEMP_PROJ"
pushd "$TEMP_PROJ" > /dev/null

cloak init e2e-app > /dev/null
assert_eq ".cloak file created" "true" "$([[ -f .cloak ]] && echo true || echo false)"

# Set project-scoped secret
cloak set LOCAL_DB_URL "postgres://local-e2e:5432" > /dev/null

# Set colliding secret that should override global for this project
cloak set -g COLLIDE_KEY "global_colliding_value" > /dev/null
cloak set COLLIDE_KEY "project_overridden_value" > /dev/null

PROJ_LIST=$(cloak list)
assert_contains "Project list has LOCAL_DB_URL" "LOCAL_DB_URL" "$PROJ_LIST"
assert_contains "Project list shows inherited global secrets" "Inherited Global Secrets" "$PROJ_LIST"

# Test execution inside project
RUN_INSIDE=$(cloak run -- sh -c 'echo "LOCAL:$LOCAL_DB_URL|GLOBAL:$E2E_GLOBAL_KEY|OVERRIDE:$COLLIDE_KEY"')
assert_eq "Inside project execution receives project + global + override" \
    "LOCAL:postgres://local-e2e:5432|GLOBAL:sk-super-secret-global-998877|OVERRIDE:project_overridden_value" \
    "$RUN_INSIDE"

popd > /dev/null

# Test execution outside project
RUN_OUTSIDE=$(cloak run -- sh -c 'echo "LOCAL:$LOCAL_DB_URL|GLOBAL:$E2E_GLOBAL_KEY|OVERRIDE:$COLLIDE_KEY"')
assert_eq "Outside project local secret is shielded and global has base value" \
    "LOCAL:|GLOBAL:sk-super-secret-global-998877|OVERRIDE:global_colliding_value" \
    "$RUN_OUTSIDE"

rm -rf "$TEMP_PROJ"

echo ""
echo ">>> [4/7] Testing Process Memory Isolation, Least Privilege & Master Key Stripping..."
cloak set -g ISOLATION_TEST "vault_memory_isolated" > /dev/null
CHILD_VAL=$(cloak run -- sh -c 'echo "$ISOLATION_TEST"')
PARENT_VAL="${ISOLATION_TEST:-}"
assert_eq "Child process received secret in memory" "vault_memory_isolated" "$CHILD_VAL"
assert_eq "Parent shell has zero leaked environment variable" "" "$PARENT_VAL"

# Test S7: Least privilege secret filtering with --keys
FILTERED_VAL=$(cloak run --keys E2E_GLOBAL_KEY -- sh -c 'echo "ALLOWED:$E2E_GLOBAL_KEY|BLOCKED:${ISOLATION_TEST:-}"')
assert_eq "Least privilege --keys filtering blocks unrequested secrets" \
    "ALLOWED:sk-super-secret-global-998877|BLOCKED:" \
    "$FILTERED_VAL"

# Test S8: CLOAK_MASTER_KEY stripped from child execution
export CLOAK_MASTER_KEY="secret-master-token"
CHILD_MASTER=$(cloak run -- sh -c 'echo "MASTER:${CLOAK_MASTER_KEY:-}"')
assert_eq "CLOAK_MASTER_KEY is stripped from child environment" \
    "MASTER:" \
    "$CHILD_MASTER"
unset CLOAK_MASTER_KEY || true

# Test N2: CLOAK_PROXY_TOKEN is stripped by default unless --proxy-token is explicitly passed
mkdir -p ~/.cloak
echo "dummy-e2e-proxy-token-42" > ~/.cloak/proxy.token
CHILD_DEFAULT_TOKEN=$(cloak run -- sh -c 'echo "PROXY_TOKEN:${CLOAK_PROXY_TOKEN:-}"')
assert_eq "CLOAK_PROXY_TOKEN is stripped by default without --proxy-token flag" \
    "PROXY_TOKEN:" \
    "$CHILD_DEFAULT_TOKEN"

CHILD_INJECTED_TOKEN=$(cloak run --proxy-token -- sh -c 'echo "PROXY_TOKEN:${CLOAK_PROXY_TOKEN:-}"')
assert_eq "CLOAK_PROXY_TOKEN is injected when --proxy-token flag is specified" \
    "PROXY_TOKEN:dummy-e2e-proxy-token-42" \
    "$CHILD_INJECTED_TOKEN"

echo ""
echo ">>> [5/7] Testing Standalone Encrypted File Vault (Argon2id + XChaCha20-Poly1305)..."
TEMP_VAULT="/tmp/test_cloak_vault_$$.enc"
export CLOAK_MASTER_KEY="correct-master-passphrase-2026"
cloak --store file --vault-path "$TEMP_VAULT" set FILE_KEY "encrypted_payload_value" > /dev/null
FILE_GET=$(cloak --store file --vault-path "$TEMP_VAULT" get FILE_KEY --reveal)
assert_eq "File vault successfully encrypts and decrypts" "encrypted_payload_value" "$FILE_GET"

# Test wrong passphrase rejection
export CLOAK_MASTER_KEY="wrong-passphrase"
WRONG_PASS_EXIT=0
cloak --store file --vault-path "$TEMP_VAULT" get FILE_KEY > /dev/null 2>&1 || WRONG_PASS_EXIT=$?
if [[ "$WRONG_PASS_EXIT" -ne 0 ]]; then
    echo "  [PASS] Wrong passphrase triggers cryptographic authentication rejection"
    PASSED=$((PASSED + 1))
else
    echo "  [FAIL] Wrong passphrase did not fail"
    FAILED=$((FAILED + 1))
fi
rm -f "$TEMP_VAULT"

echo ""
echo ">>> [6/7] Testing Local AI Loopback Proxy (:4149) & Authentication..."
# Start proxy on alternate port 4149 to avoid collision
cloak proxy --port 4149 > /dev/null 2>&1 &
PROXY_PID=$!
sleep 1.2

HEALTH_JSON=$(curl -s http://127.0.0.1:4149/health || echo "{}")
assert_contains "Proxy health report active" '"status":"active"' "$HEALTH_JSON"
assert_eq "Unauthenticated health hides providers" "false" "$([[ "$HEALTH_JSON" == *'"providers"'* ]] && echo true || echo false)"

TOKEN=$(cat ~/.cloak/proxy.token 2>/dev/null || echo "")
# Test authenticated session detection
AUTH_HEALTH=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4149/health || echo "{}")
assert_contains "Proxy detects authenticated session" '"authenticated":true' "$AUTH_HEALTH"
assert_contains "Authenticated proxy health lists providers" '"providers"' "$AUTH_HEALTH"

# Test S1: Unauthenticated request to protected endpoint is rejected
UNAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:4149/v1/chat/completions -d '{"messages":[]}' || echo "000")
assert_eq "Unauthenticated request to proxy is rejected with 401" "401" "$UNAUTH_STATUS"

# Test S1: Path not in allowlist is rejected with 403
INVALID_PATH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4149/v1/unauthorized/path || echo "000")
assert_eq "Disallowed path is rejected with 403" "403" "$INVALID_PATH_STATUS"

# Test proxy.info file exists
INFO_JSON=$(cat ~/.cloak/proxy.info 2>/dev/null || echo "{}")
assert_contains "proxy.info contains port 4149" '"port": 4149' "$INFO_JSON"

# Set test secret for outbound injection testing
cloak set -g CLOAK_TEST_KEY "injected-secret-val-99" > /dev/null

# Test /cloak/forward gateway endpoint
FORWARD_RES=""
for attempt in 1 2 3; do
    FORWARD_RES=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Cloak-Target: https://httpbin.org/headers" http://127.0.0.1:4149/cloak/forward || echo "{}")
    if [[ "$FORWARD_RES" == *"injected-secret-val-99"* ]]; then
        break
    fi
    sleep 1
done
assert_contains "Forward gateway reaches target and injects header" "injected-secret-val-99" "$FORWARD_RES"

# Test HTTPS CONNECT transparent forward proxying with CA verification
CONNECT_RES=""
for attempt in 1 2 3; do
    CONNECT_RES=$(curl -s -x http://127.0.0.1:4149 --cacert "$CA_PATH" https://httpbin.org/headers || echo "{}")
    if [[ "$CONNECT_RES" == *"injected-secret-val-99"* ]]; then
        break
    fi
    sleep 1
done
assert_contains "HTTPS MITM proxy intercepts and injects secret" "injected-secret-val-99" "$CONNECT_RES"

# Test cloak run --proxy child process transparent proxying & CA trust
CHILD_PROXY_RES=""
for attempt in 1 2 3; do
    CHILD_PROXY_RES=$(cloak run --proxy --proxy-port 4149 -- curl -s https://httpbin.org/headers || echo "{}")
    if [[ "$CHILD_PROXY_RES" == *"injected-secret-val-99"* ]]; then
        break
    fi
    sleep 1
done
assert_contains "Child process inside cloak run auto-routes through MITM proxy" "injected-secret-val-99" "$CHILD_PROXY_RES"

cloak delete -g CLOAK_TEST_KEY > /dev/null 2>&1 || true

# Test authenticated graceful shutdown via /cloak/shutdown
SHUTDOWN_RES=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4149/cloak/shutdown || echo "{}")
assert_contains "Graceful shutdown response" '"status":"shutting_down"' "$SHUTDOWN_RES"
sleep 0.5

# Test proxy process stopped and proxy.info cleaned up
PROXY_RUNNING=0
kill -0 $PROXY_PID 2>/dev/null && PROXY_RUNNING=1 || PROXY_RUNNING=0
assert_eq "Proxy daemon stopped after /cloak/shutdown" "0" "$PROXY_RUNNING"
assert_eq "proxy.info cleaned up after shutdown" "false" "$([[ -f ~/.cloak/proxy.info ]] && echo true || echo false)"

echo ""
echo ">>> [7/7] Testing GUI & Desktop App Assets..."
pushd gui > /dev/null
BUILD_RES=$(pnpm run build 2>&1)
assert_contains "Frontend builds cleanly with pnpm" "built in" "$BUILD_RES"

assert_eq "dist/index.html exists" "true" "$([[ -f dist/index.html ]] && echo true || echo false)"
popd > /dev/null

# Check cloak-gui desktop binary portably
GUI_BIN=$(command -v cloak-gui || echo "${HOME}/.cargo/bin/cloak-gui")
assert_eq "cloak-gui desktop binary exists" "true" "$([[ -x "$GUI_BIN" ]] && echo true || echo false)"
GUI_DYLIBS=$(otool -L "$GUI_BIN" | grep -E "Security|WebKit|AppKit" || true)
assert_contains "cloak-gui links to Apple Security framework" "Security.framework" "$GUI_DYLIBS"
assert_contains "cloak-gui links to Apple AppKit framework" "AppKit.framework" "$GUI_DYLIBS"

# Clean up test keys from macOS keychain
cloak delete -g E2E_GLOBAL_KEY > /dev/null 2>&1 || true
cloak delete -g COLLIDE_KEY > /dev/null 2>&1 || true
cloak delete -g ISOLATION_TEST > /dev/null 2>&1 || true

echo ""
echo "================================================================"
echo "    VERIFICATION SUMMARY: ${PASSED} PASSED, ${FAILED} FAILED"
echo "================================================================"

if [[ "$FAILED" -gt 0 ]]; then
    exit 1
fi
