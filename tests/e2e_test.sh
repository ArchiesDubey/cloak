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
assert_contains "CLI Version Check" "cloak 0.1.0" "$VERSION_OUT"

HELP_OUT=$(cloak --help)
assert_contains "Help includes proxy subcommand" "proxy" "$HELP_OUT"
assert_contains "Help includes gui subcommand" "gui" "$HELP_OUT"
assert_contains "Help includes init subcommand" "init" "$HELP_OUT"

echo ""
echo ">>> [2/7] Testing Global Secrets Storage & Masking (macOS Keychain)..."
cloak set -g E2E_GLOBAL_KEY "sk-super-secret-global-998877"
LIST_OUT=$(cloak list -g)
assert_contains "Global Secret in list" "E2E_GLOBAL_KEY" "$LIST_OUT"

GET_MASKED=$(cloak get -g E2E_GLOBAL_KEY)
assert_contains "Get masked displays asterisk mask" "sk-s****8877" "$GET_MASKED"

GET_REVEAL=$(cloak get -g E2E_GLOBAL_KEY --reveal)
assert_eq "Get --reveal shows raw value" "sk-super-secret-global-998877" "$GET_REVEAL"

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
echo ">>> [4/7] Testing Process Memory Isolation..."
cloak set -g ISOLATION_TEST "vault_memory_isolated" > /dev/null
CHILD_VAL=$(cloak run -- sh -c 'echo "$ISOLATION_TEST"')
PARENT_VAL="${ISOLATION_TEST:-}"
assert_eq "Child process received secret in memory" "vault_memory_isolated" "$CHILD_VAL"
assert_eq "Parent shell has zero leaked environment variable" "" "$PARENT_VAL"

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
echo ">>> [6/7] Testing Local AI Loopback Proxy (:4149)..."
# Start proxy on alternate port 4149 to avoid collision
cloak proxy --port 4149 > /dev/null 2>&1 &
PROXY_PID=$!
sleep 1.2

HEALTH_JSON=$(curl -s http://127.0.0.1:4149/health || echo "{}")
assert_contains "Proxy health report active" '"status":"active"' "$HEALTH_JSON"
assert_contains "Proxy health lists providers" '"providers"' "$HEALTH_JSON"

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true

echo ""
echo ">>> [7/7] Testing GUI & Desktop App Assets..."
pushd gui > /dev/null
BUILD_RES=$(pnpm run build 2>&1)
assert_contains "Frontend builds cleanly with pnpm" "built in" "$BUILD_RES"

assert_eq "dist/index.html exists" "true" "$([[ -f dist/index.html ]] && echo true || echo false)"
popd > /dev/null

# Check cloak-gui desktop binary
assert_eq "cloak-gui desktop binary exists in PATH" "true" "$([[ -x /Users/archiesdubey/.cargo/bin/cloak-gui ]] && echo true || echo false)"
GUI_DYLIBS=$(otool -L /Users/archiesdubey/.cargo/bin/cloak-gui | grep -E "Security|WebKit|AppKit" || true)
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
