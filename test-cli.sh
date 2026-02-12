#!/bin/bash

# Bahll CLI Test Suite

TESTS_PASSED=0
TESTS_FAILED=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

# Test 1: Hash commands
print_test "Testing SHA-256 hashing"
RESULT=$(php bahll.php hash sha256 "test" 2>&1 | grep -oE '[a-f0-9]{64}')
if [ ! -z "$RESULT" ]; then
    pass "SHA-256 hash generated: $RESULT"
else
    fail "SHA-256 hash failed"
fi

# Test 2: bcrypt
print_test "Testing bcrypt hashing"
RESULT=$(php bahll.php hash bcrypt "password" 2>&1 | grep -oE '\$2[ay]\$[0-9]{2}\$[./A-Za-z0-9]{53}')
if [ ! -z "$RESULT" ]; then
    pass "bcrypt hash generated"
else
    fail "bcrypt hash failed"
fi

# Test 3: Random bytes
print_test "Testing random bytes generation"
RESULT=$(php bahll.php random bytes 32 2>&1 | grep -oE '[a-f0-9]{64}')
if [ ! -z "$RESULT" ]; then
    pass "Random bytes generated"
else
    fail "Random bytes generation failed"
fi

# Test 4: Base64 encoding
print_test "Testing Base64 encoding"
RESULT=$(php bahll.php encoding base64 "Hello" 2>&1 | grep -oE 'SGVsbG8=')
if [ ! -z "$RESULT" ]; then
    pass "Base64 encoding successful"
else
    fail "Base64 encoding failed"
fi

# Test 5: Hex encoding
print_test "Testing Hex encoding"
RESULT=$(php bahll.php encoding hex "test" 2>&1 | grep -oE '74657374')
if [ ! -z "$RESULT" ]; then
    pass "Hex encoding successful"
else
    fail "Hex encoding failed"
fi

# Test 6: Encryption/Decryption
print_test "Testing AES-256-GCM encryption"
RESULT=$(php bahll.php encrypt aes-256-gcm "secret" "key" 2>&1 | grep -oE 'eyJ[A-Za-z0-9+/=]+')
if [ ! -z "$RESULT" ]; then
    pass "AES-256-GCM encryption successful"
    
    # Test decryption
    print_test "Testing AES-256-GCM decryption"
    DECRYPTED=$(php bahll.php decrypt aes-256-gcm "$RESULT" "key" 2>&1 | grep -oE '^secret$|secret')
    if [[ "$DECRYPTED" == *"secret"* ]]; then
        pass "AES-256-GCM decryption successful"
    else
        fail "AES-256-GCM decryption failed"
    fi
else
    fail "AES-256-GCM encryption failed"
fi

# Test 7: Help commands
print_test "Testing --help flag"
RESULT=$(php bahll.php --help 2>&1 | grep -c "MAIN COMMANDS")
if [ "$RESULT" -gt 0 ]; then
    pass "Help command successful"
else
    fail "Help command failed"
fi

# Test 8: Version command
print_test "Testing --version flag"
RESULT=$(php bahll.php --version 2>&1 | grep -c "Bahll Cryptography Suite")
if [ "$RESULT" -gt 0 ]; then
    pass "Version command successful"
else
    fail "Version command failed"
fi

# Test 9: Audit check
print_test "Testing audit check"
RESULT=$(php bahll.php audit check 2>&1 | grep -c "System OK\|System OK")
if [ "$RESULT" -gt 0 ]; then
    pass "Audit check successful"
else
    fail "Audit check failed"
fi

# Test 10: Logs command
print_test "Testing logs view"
RESULT=$(php bahll.php logs view 2>&1 | grep -c "Recent Activity\|Recent Activity")
if [ "$RESULT" -gt 0 ]; then
    pass "Logs view successful"
else
    fail "Logs view failed"
fi

# Test 11: Error handling - unknown command
print_test "Testing error handling for unknown command"
RESULT=$(php bahll.php unknown-cmd 2>&1 | grep -c "Command not found")
if [ "$RESULT" -gt 0 ]; then
    pass "Error handling successful"
else
    fail "Error handling failed"
fi

# Test 12: Error handling - missing data
print_test "Testing error handling for missing data"
RESULT=$(php bahll.php hash sha256 2>&1 | grep -c "No data provided\|Hash & Key")
if [ "$RESULT" -gt 0 ]; then
    pass "Missing data error handling successful"
else
    fail "Missing data error handling failed"
fi

# Test 13: SHA-512
print_test "Testing SHA-512"
RESULT=$(php bahll.php hash sha512 "test" 2>&1 | grep -oE '[a-f0-9]{128}')
if [ ! -z "$RESULT" ]; then
    pass "SHA-512 hash generated"
else
    fail "SHA-512 hash failed"
fi

# Test 14: Random string
print_test "Testing random string"
RESULT=$(php bahll.php random string 10 2>&1 | grep -oE '[A-Za-z0-9]{10}')
if [ ! -z "$RESULT" ]; then
    pass "Random string generated"
else
    fail "Random string generation failed"
fi

# Test 15: RSA key generation
print_test "Testing RSA-2048 key generation"
RESULT=$(php bahll.php asymmetric generate rsa-2048 2>&1 | grep -c "BEGIN")
if [ "$RESULT" -gt 0 ]; then
    pass "RSA-2048 key generated"
else
    fail "RSA-2048 key generation failed"
fi

echo ""
echo "================================"
echo "Test Results:"
echo "  Passed: ${GREEN}$TESTS_PASSED${NC}"
echo "  Failed: ${RED}$TESTS_FAILED${NC}"
echo "  Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo "================================"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
