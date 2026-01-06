#!/bin/bash
# X3 IRC Services - Static Analysis Script
#
# This script runs static analysis tools on the X3 codebase.
# Tools supported:
#   - cppcheck: General purpose C static analyzer
#   - scan-build: Clang static analyzer (optional)
#
# Usage:
#   ./tools/static-analysis.sh [cppcheck|scan-build|all]
#
# Requirements:
#   - cppcheck: apt install cppcheck
#   - scan-build: apt install clang-tools (provides scan-build)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
X3_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$X3_DIR/src"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 [cppcheck|scan-build|all]"
    echo ""
    echo "Options:"
    echo "  cppcheck    Run cppcheck static analyzer"
    echo "  scan-build  Run clang scan-build analyzer"
    echo "  all         Run all available analyzers (default)"
    echo ""
    echo "Environment variables:"
    echo "  CPPCHECK_OPTS   Additional options for cppcheck"
    echo "  SCAN_BUILD_OPTS Additional options for scan-build"
    exit 1
}

check_tool() {
    local tool=$1
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${YELLOW}Warning: $tool not found, skipping${NC}"
        return 1
    fi
    return 0
}

run_cppcheck() {
    echo -e "${GREEN}=== Running cppcheck ===${NC}"

    if ! check_tool cppcheck; then
        return 0
    fi

    local opts=(
        --enable=warning,style,performance,portability
        --std=c11
        -I "$SRC_DIR"
        -D WITH_KEYCLOAK=1
        -D WITH_LMDB=1
        -D WITH_SSL=1
        -D WITH_PROTOCOL_P10=1
        -D WITH_IOSET_EPOLL=1
        -D _GNU_SOURCE=1
        --suppress=variableScope
        --suppress=unusedFunction
        --suppress=unusedStructMember
        --force
        --quiet
        $CPPCHECK_OPTS
    )

    echo "Running: cppcheck ${opts[*]} $SRC_DIR/*.c"

    # Run cppcheck and capture output
    local output
    local exit_code=0
    output=$(cppcheck "${opts[@]}" "$SRC_DIR"/*.c 2>&1) || exit_code=$?

    if [ -n "$output" ]; then
        echo "$output"
    fi

    # Count issues
    local error_count=$(echo "$output" | grep -c "error:" || true)
    local warning_count=$(echo "$output" | grep -c "warning:" || true)
    local style_count=$(echo "$output" | grep -c "style:" || true)

    echo ""
    echo "cppcheck summary:"
    echo "  Errors:   $error_count"
    echo "  Warnings: $warning_count"
    echo "  Style:    $style_count"

    if [ "$error_count" -gt 0 ]; then
        echo -e "${RED}cppcheck found errors${NC}"
        return 1
    elif [ "$warning_count" -gt 0 ]; then
        echo -e "${YELLOW}cppcheck found warnings${NC}"
    else
        echo -e "${GREEN}cppcheck: No issues found${NC}"
    fi

    return 0
}

run_scan_build() {
    echo -e "${GREEN}=== Running scan-build (Clang Static Analyzer) ===${NC}"

    if ! check_tool scan-build; then
        return 0
    fi

    # Check if configure has been run
    if [ ! -f "$X3_DIR/Makefile" ]; then
        echo -e "${YELLOW}Warning: X3 not configured. Run ./configure first.${NC}"
        echo "Skipping scan-build (requires configured build)"
        return 0
    fi

    local report_dir="$X3_DIR/scan-build-report"
    rm -rf "$report_dir"
    mkdir -p "$report_dir"

    local opts=(
        -o "$report_dir"
        --status-bugs
        -enable-checker security.insecureAPI.strcpy
        -enable-checker security.insecureAPI.sprintf
        -enable-checker alpha.security.ArrayBoundV2
        -enable-checker alpha.core.BoolAssignment
        $SCAN_BUILD_OPTS
    )

    echo "Running: scan-build ${opts[*]} make -C $X3_DIR/src"

    # Clean first to ensure full analysis
    make -C "$X3_DIR/src" clean 2>/dev/null || true

    # Run scan-build
    local exit_code=0
    scan-build "${opts[@]}" make -C "$X3_DIR/src" || exit_code=$?

    if [ "$exit_code" -ne 0 ]; then
        echo -e "${RED}scan-build found bugs${NC}"
        echo "View report: scan-view $report_dir/*/index.html"
        return 1
    else
        echo -e "${GREEN}scan-build: No bugs found${NC}"
        rm -rf "$report_dir"
    fi

    return 0
}

# Main
cd "$X3_DIR"

case "${1:-all}" in
    cppcheck)
        run_cppcheck
        ;;
    scan-build)
        run_scan_build
        ;;
    all)
        run_cppcheck
        echo ""
        run_scan_build
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        echo "Unknown option: $1"
        usage
        ;;
esac

echo ""
echo -e "${GREEN}Static analysis complete${NC}"
