#!/bin/bash

# Script to run each test individually with a timeout
# This prevents one hanging test from blocking all others

TIMEOUT=15
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0
TIMEOUTS=0

echo "Running tests individually with ${TIMEOUT}s timeout each..."
echo ""

# Get list of all test functions
TESTS=$(go test -list . 2>&1 | grep "^Test" | grep -v "^ok")
TOTAL_TESTS=$(echo "$TESTS" | wc -l | tr -d ' ')

for test in $TESTS; do
    TOTAL=$((TOTAL + 1))
    printf "[%3d/%3d] %-50s " $TOTAL $TOTAL_TESTS "$test"
    
    # Run test with timeout
    if timeout $TIMEOUT go test -run "^${test}$" -v > /tmp/test_${test}.log 2>&1; then
        result=$(tail -1 /tmp/test_${test}.log)
        if echo "$result" | grep -q "^ok"; then
            echo "PASS"
            PASSED=$((PASSED + 1))
        elif echo "$result" | grep -q "SKIP"; then
            echo "SKIP"
            SKIPPED=$((SKIPPED + 1))
        else
            echo "FAIL"
            FAILED=$((FAILED + 1))
        fi
    else
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "TIMEOUT"
            TIMEOUTS=$((TIMEOUTS + 1))
            FAILED=$((FAILED + 1))
        else
            echo "FAIL"
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo ""
echo "Summary:"
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED (including $TIMEOUTS timeouts)"
echo "  Skipped: $SKIPPED"

if [ $FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi

