#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== DNS Tool Contract Test Suite ==="
echo ""

FAILED=0

echo "--- 1. Schema Validation Tests ---"
if python -m pytest tests/test_schema_validation.py -v --tb=short 2>&1; then
    echo "[PASS] Schema validation"
else
    echo "[FAIL] Schema validation"
    FAILED=1
fi
echo ""

echo "--- 2. Golden Fixture Regression Tests ---"
if python -m pytest tests/test_golden.py -v --tb=short 2>&1; then
    echo "[PASS] Golden fixtures"
else
    echo "[FAIL] Golden fixtures"
    FAILED=1
fi
echo ""

echo "--- 3. Dependency Injection Tests ---"
if python -m pytest tests/test_dns_analyzer.py::TestDependencyInjection -v --tb=short 2>&1; then
    echo "[PASS] Dependency injection"
else
    echo "[FAIL] Dependency injection"
    FAILED=1
fi
echo ""

echo "--- 4. Full Test Suite ---"
if python -m pytest tests/ -v --tb=short 2>&1; then
    echo "[PASS] Full suite"
else
    echo "[FAIL] Full suite (some tests may have pre-existing failures)"
    FAILED=1
fi
echo ""

echo "==================================="
if [ $FAILED -eq 0 ]; then
    echo "ALL CONTRACT TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED - see output above"
    exit 1
fi
