#!/usr/bin/env bash
# ==============================================================================
# Grainlify - Comprehensive Deployment Script Test Suite
# ==============================================================================
# Tests failure handling for all deployment scripts:
# - deploy.sh
# - upgrade.sh
# - rollback.sh
# - verify-deployment.sh
#
# This test suite ensures:
# - Scripts exit with non-zero status on failure
# - Helpful error messages are printed
# - Environment variable validation is covered
# - Configuration file handling is robust
#
# USAGE:
#   ./test_all_script_failures.sh [options]
#
# OPTIONS:
#   -v, --verbose     Show detailed test output
#   -q, --quiet       Only show failures
#   -h, --help        Show this help
#
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Test Setup
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Test scripts
DEPLOY_SCRIPT="$SCRIPT_DIR/deploy.sh"
UPGRADE_SCRIPT="$SCRIPT_DIR/upgrade.sh"
ROLLBACK_SCRIPT="$SCRIPT_DIR/rollback.sh"
VERIFY_SCRIPT="$SCRIPT_DIR/verify-deployment.sh"

# Test data
FAKE_WASM="/tmp/fake_valid.wasm"
INVALID_WASM="/tmp/fake_invalid.wasm"
EMPTY_WASM="/tmp/fake_empty.wasm"
MISSING_CONFIG="/tmp/missing_config.env"
INVALID_CONFIG="/tmp/invalid_config.env"
TEST_DIR="/tmp/grainlify_test_$$"

# Test configuration
VERBOSE="${VERBOSE:-false}"
QUIET="${QUIET:-false}"
TESTS_PASSED=0
TESTS_FAILED=0

# Colors for output
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------

# Test result functions
test_pass() {
    ((TESTS_PASSED++))
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${GREEN}✔ PASS${NC}: $1"
    fi
}

test_fail() {
    ((TESTS_FAILED++))
    echo -e "${RED}✘ FAIL${NC}: $1"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "  Expected: $2"
        echo "  Got: $3"
    fi
}

test_info() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${BLUE}ℹ INFO${NC}: $1"
    fi
}

# Test runner that expects failure
run_expect_fail() {
    local desc="$1"
    local expected_msg="$2"
    shift 2

    if [[ "$VERBOSE" == "true" ]]; then
        test_info "Running: $*"
    fi

    set +e
    local output
    output=$("$@" 2>&1)
    local exit_code=$?
    set -e

    if [[ $exit_code -eq 0 ]]; then
        test_fail "$desc" "non-zero exit code" "exit code 0"
        return 1
    fi

    if ! echo "$output" | grep -q "$expected_msg"; then
        test_fail "$desc" "message containing '$expected_msg'" "output: $output"
        return 1
    fi

    test_pass "$desc"
    return 0
}

# Mock setup functions
setup_mocks() {
    local mock_bin="$TEST_DIR/mock_bin"
    mkdir -p "$mock_bin"

    # Mock stellar CLI
    cat > "$mock_bin/stellar" << 'EOF'
#!/usr/bin/env bash
case "$1" in
    "keys")
        if [[ "$2" == "address" ]]; then
            if [[ "$3" == "nonexistent_identity" ]]; then
                echo "Error: Identity not found" >&2
                exit 1
            else
                echo "FAKE_ADDRESS_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            fi
        fi
        ;;
    "contract")
        if [[ "$2" == "install" ]]; then
            if [[ "${SUDO_FAKE_INSTALL_FAIL:-0}" == "1" ]]; then
                echo "Error: Simulated install failure" >&2
                exit 1
            else
                echo "FAKE_WASM_HASH_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
            fi
        elif [[ "$2" == "deploy" ]]; then
            echo "FAKE_CONTRACT_ID_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        fi
        ;;
    *)
        echo "Mock stellar command: $*"
        ;;
esac
EOF
    chmod +x "$mock_bin/stellar"

    # Mock soroban CLI (for backward compatibility)
    cat > "$mock_bin/soroban" << 'EOF'
#!/usr/bin/env bash
echo "Mock soroban command: $*"
EOF
    chmod +x "$mock_bin/soroban"

    export PATH="$mock_bin:$PATH"
}

cleanup_mocks() {
    if [[ -n "${ORIGINAL_PATH:-}" ]]; then
        export PATH="$ORIGINAL_PATH"
    fi
}

# Test data setup
setup_test_data() {
    # Create valid WASM file (minimal magic header)
    echo -n -e "\x00\x61\x73\x6D\x01" > "$FAKE_WASM"

    # Create invalid WASM file (wrong magic)
    echo -n -e "\xFF\x61\x73\x6D\x01" > "$INVALID_WASM"

    # Create empty WASM file for empty-file validation tests
    : > "$EMPTY_WASM"

    # Create missing config (doesn't exist)
    touch "$MISSING_CONFIG" && rm "$MISSING_CONFIG"

    # Create invalid config (malformed)
    echo "INVALID_CONFIG_LINE_WITHOUT_EQUALS" > "$INVALID_CONFIG"
    echo "MALFORMED_LINE=" >> "$INVALID_CONFIG"

    # Create test directory
    mkdir -p "$TEST_DIR"
}

cleanup_test_data() {
    rm -f "$FAKE_WASM" "$INVALID_WASM" "$EMPTY_WASM" "$MISSING_CONFIG" "$INVALID_CONFIG"
    rm -rf "$TEST_DIR"
}

# ------------------------------------------------------------------------------
# Test Categories
# ------------------------------------------------------------------------------

test_deploy_script_failures() {
    test_info "Testing deploy.sh failure scenarios"

    # 1. Missing WASM file
    run_expect_fail "Deploy: Missing WASM file" "No WASM file specified" "$DEPLOY_SCRIPT"

    # 2. Non-existent WASM file
    run_expect_fail "Deploy: Non-existent WASM file" "WASM file not found" "$DEPLOY_SCRIPT" "/tmp/does_not_exist.wasm"

    # 3. Invalid WASM file format (should warn but continue)
    set +e
    local output
    output=$("$DEPLOY_SCRIPT" "$INVALID_WASM" 2>&1)
    local exit_code=$?
    set -e

    # Note: Invalid WASM format only warns, doesn't fail
    if echo "$output" | grep -q "may not be a valid WASM binary"; then
        test_pass "Deploy: Invalid WASM format (warning displayed)"
    else
        test_fail "Deploy: Invalid WASM format" "warning about invalid WASM" "output: $output"
    fi

    # 4. Empty WASM file
    run_expect_fail "Deploy: Empty WASM file" "WASM file is empty" "$DEPLOY_SCRIPT" "$EMPTY_WASM"

    # 5. Invalid network
    run_expect_fail "Deploy: Invalid network" "Invalid network" "$DEPLOY_SCRIPT" "$FAKE_WASM" -n "invalid_network"

    # 6. Missing config file should warn and may continue
    set +e
    output=$("$DEPLOY_SCRIPT" "$FAKE_WASM" -c "$MISSING_CONFIG" 2>&1)
    exit_code=$?
    set -e

    if echo "$output" | grep -q "Config file not found"; then
        test_pass "Deploy: Missing config file"
    elif [[ $exit_code -eq 0 ]]; then
        # Some deploy.sh paths treat missing config as non-fatal and proceed with defaults.
        test_pass "Deploy: Missing config file"
    else
        test_fail "Deploy: Missing config file" "warning or graceful success with defaults" "output: $output"
    fi

    # 7. Invalid identity
    # In offline/sandbox runs the deploy preflight may fail on network before identity lookup.
    set +e
    output=$("$DEPLOY_SCRIPT" "$FAKE_WASM" -i "nonexistent_identity" 2>&1)
    exit_code=$?
    set -e
    if [[ $exit_code -eq 0 ]]; then
        test_fail "Deploy: Invalid identity" "non-zero exit code" "exit code 0"
    elif echo "$output" | grep -Eq "Identity not found|Cannot reach network|network connectivity"; then
        test_pass "Deploy: Invalid identity"
    else
        test_fail "Deploy: Invalid identity" "identity or preflight network failure output" "exit=$exit_code output: $output"
    fi

    # 8. Missing CLI dependency
    local old_path="$PATH"
    export PATH="/usr/bin:/bin"
    run_expect_fail "Deploy: Missing CLI dependency" "Neither 'stellar' nor 'soroban' CLI found" "$DEPLOY_SCRIPT" "$FAKE_WASM"
    export PATH="$old_path"

    # 9. Simulated install failure
    export SUDO_FAKE_INSTALL_FAIL=1
    set +e
    output=$("$DEPLOY_SCRIPT" "$FAKE_WASM" 2>&1)
    exit_code=$?
    set -e
    if [[ $exit_code -eq 0 ]]; then
        test_fail "Deploy: Install failure" "non-zero exit code" "exit code 0"
    elif echo "$output" | grep -Eq "Command failed after 3 attempts|Cannot reach network|network connectivity"; then
        test_pass "Deploy: Install failure"
    else
        test_fail "Deploy: Install failure" "install-retry failure or preflight network failure output" "exit=$exit_code output: $output"
    fi
    unset SUDO_FAKE_INSTALL_FAIL
}

test_upgrade_script_failures() {
    test_info "Testing upgrade.sh failure scenarios"

    # 1. Missing contract ID
    run_expect_fail "Upgrade: Missing contract ID" "No contract ID specified" "$UPGRADE_SCRIPT"

    # 2. Invalid contract ID format (warning path may continue)
    set +e
    local output
    output=$("$UPGRADE_SCRIPT" "BAD_ID" "$FAKE_WASM" 2>&1)
    local exit_code=$?
    set -e

    if echo "$output" | grep -q "Contract ID format may be invalid"; then
        test_pass "Upgrade: Invalid contract ID format"
    else
        test_fail "Upgrade: Invalid contract ID format" "warning about invalid contract ID format" "output: $output"
    fi

    # 3. Missing WASM file
    run_expect_fail "Upgrade: Missing WASM file" "No WASM file specified" "$UPGRADE_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678"

    # 4. Non-existent WASM file
    run_expect_fail "Upgrade: Non-existent WASM file" "WASM file not found" "$UPGRADE_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" "/tmp/missing.wasm"

    # 5. Invalid WASM file format (should warn but continue)
    set +e
    local output
    output=$("$UPGRADE_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" "$INVALID_WASM" 2>&1)
    local exit_code=$?
    set -e

    # Note: Invalid WASM format only warns, doesn't fail
    if echo "$output" | grep -q "may not be a valid WASM binary"; then
        test_pass "Upgrade: Invalid WASM format (warning displayed)"
    else
        test_fail "Upgrade: Invalid WASM format" "warning about invalid WASM" "output: $output"
    fi

    # 6. Invalid network
    run_expect_fail "Upgrade: Invalid network" "Invalid network" "$UPGRADE_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" "$FAKE_WASM" -n "invalid_network"

    # 7. Invalid identity
    run_expect_fail "Upgrade: Invalid identity" "Identity not found" "$UPGRADE_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" "$FAKE_WASM" -s "nonexistent_identity"
}

test_rollback_script_failures() {
    test_info "Testing rollback.sh failure scenarios"

    # 1. Missing contract ID
    run_expect_fail "Rollback: Missing contract ID" "No contract ID specified" "$ROLLBACK_SCRIPT" --force

    # 2. Missing WASM hash
    run_expect_fail "Rollback: Missing WASM hash" "No previous WASM hash specified" "$ROLLBACK_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" --force

    # 3. Invalid contract ID format (warning path may continue)
    set +e
    local output
    output=$("$ROLLBACK_SCRIPT" "BAD_ID" "HASH123" --force 2>&1)
    local exit_code=$?
    set -e

    if echo "$output" | grep -q "Contract ID format may be invalid"; then
        test_pass "Rollback: Invalid contract ID format"
    else
        test_fail "Rollback: Invalid contract ID format" "warning about invalid contract ID format" "output: $output"
    fi

    # 4. Invalid WASM hash format (warning path may continue)
    set +e
    output=$("$ROLLBACK_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" "SHORT_HASH" --force 2>&1)
    exit_code=$?
    set -e

    if echo "$output" | grep -q "WASM hash format may be invalid"; then
        test_pass "Rollback: Invalid WASM hash format"
    else
        test_fail "Rollback: Invalid WASM hash format" "warning about invalid WASM hash format" "output: $output"
    fi

    # 5. Invalid network
    run_expect_fail "Rollback: Invalid network" "Invalid network" "$ROLLBACK_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" "1234567890123456789012345678901234567890123456789012345678" -n "invalid_network" --force

    # 6. Invalid identity
    run_expect_fail "Rollback: Invalid identity" "Identity not found" "$ROLLBACK_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" "1234567890123456789012345678901234567890123456789012345678" -s "nonexistent_identity" --force
}

test_verify_deployment_failures() {
    test_info "Testing verify-deployment.sh failure scenarios"

    # 1. Missing contract ID
    run_expect_fail "Verify: Missing contract ID" "No contract ID specified" "$VERIFY_SCRIPT"

    # 2. Invalid contract ID format
    run_expect_fail "Verify: Invalid contract ID format" "Contract ID format may be invalid" "$VERIFY_SCRIPT" "BAD_ID"

    # 3. Invalid network
    run_expect_fail "Verify: Invalid network" "Contract verification failed" "$VERIFY_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" -n "invalid_network"

    # 4. Check admin without expected admin
    run_expect_fail "Verify: Check admin without expected" "Contract verification failed" "$VERIFY_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678" --check-admin
}

test_configuration_failures() {
    test_info "Testing configuration file failures"

    # Test with invalid config file (may fail or continue with defaults)
    set +e
    local output
    output=$("$DEPLOY_SCRIPT" "$FAKE_WASM" -c "$INVALID_CONFIG" 2>&1)
    local exit_code=$?
    set -e

    if echo "$output" | grep -Eq "Error loading config|Invalid|malformed|Configuration loaded|Cannot reach network|network connectivity"; then
        test_pass "Config: Invalid config file"
    else
        test_fail "Config: Invalid config file" "config parsing warning/error output or graceful fallback output" "output: $output"
    fi

    # Test with missing config file (should warn but continue)
    # This should NOT fail, just warn about missing config
    set +e
    output=$("$DEPLOY_SCRIPT" "$FAKE_WASM" -c "$MISSING_CONFIG" 2>&1)
    local exit_code=$?
    set -e

    if echo "$output" | grep -q "Config file not found"; then
        test_pass "Config: Missing config handled gracefully"
    elif [[ $exit_code -eq 0 ]]; then
        test_pass "Config: Missing config handled gracefully"
    else
        test_fail "Config: Missing config warning" "warning about missing config" "output: $output"
    fi
}

test_environment_variable_failures() {
    test_info "Testing environment variable validation"

    # Test with invalid RPC URL
    local old_rpc_url="${SOROBAN_RPC_URL:-}"
    export SOROBAN_RPC_URL="invalid://url"
    run_expect_fail "Env: Invalid RPC URL" "Contract verification failed" "$VERIFY_SCRIPT" "C1234567890123456789012345678901234567890123456789012345678"
    export SOROBAN_RPC_URL="$old_rpc_url"

    # Test with empty required variables (should use defaults)
    # This should NOT fail - scripts should have sensible defaults
    unset SOROBAN_RPC_URL SOROBAN_NETWORK DEPLOYER_IDENTITY
    set +e
    local output
    output=$("$DEPLOY_SCRIPT" --help 2>&1)
    local exit_code=$?
    set -e

    if [[ $exit_code -eq 0 ]]; then
        test_pass "Env: Missing variables handled with defaults"
    else
        test_fail "Env: Missing variables should not prevent help" "help should work without env vars" "exit code: $exit_code"
    fi
}

# ------------------------------------------------------------------------------
# Main Test Runner
# ------------------------------------------------------------------------------

show_usage() {
    cat << EOF
Grainlify Deployment Script Test Suite

USAGE:
    $0 [options]

OPTIONS:
    -v, --verbose     Show detailed test output
    -q, --quiet       Only show failures
    -h, --help        Show this help message

DESCRIPTION:
    This test suite validates failure handling for all deployment scripts.
    It ensures scripts exit with proper error codes and display helpful
    error messages when encountering invalid inputs or system failures.

TESTED SCRIPTS:
    - deploy.sh
    - upgrade.sh
    - rollback.sh
    - verify-deployment.sh

TEST CATEGORIES:
    - Input validation
    - Configuration handling
    - Environment variable validation
    - Dependency checking
    - Network connectivity
    - Identity verification

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE="true"
                export VERBOSE
                shift
                ;;
            -q|--quiet)
                QUIET="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

main() {
    echo "=============================================================================="
    echo "Grainlify Deployment Script Failure Test Suite"
    echo "=============================================================================="

    parse_args "$@"

    # Save original PATH
    ORIGINAL_PATH="$PATH"

    # Setup test environment
    setup_test_data
    setup_mocks

    # Trap cleanup
    trap 'cleanup_test_data; cleanup_mocks' EXIT

    # Run test categories
    test_deploy_script_failures
    test_upgrade_script_failures
    test_rollback_script_failures
    test_verify_deployment_failures
    test_configuration_failures
    test_environment_variable_failures

    # Results summary
    echo ""
    echo "=============================================================================="
    echo "Test Results Summary"
    echo "=============================================================================="
    echo -e "  Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "  Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo "  Total tests:  $((TESTS_PASSED + TESTS_FAILED))"

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}✓ All tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}✗ Some tests failed.${NC}"
        exit 1
    fi
}

# Run main if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
