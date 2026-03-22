#!/bin/bash
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
#
# Multi-distro integration test runner for terok-shield.
#
# Builds test containers for each target distro and runs the
# integration test suite inside them. Requires a modern host
# with podman and privileges to run nested containers.
#
# Usage:
#   ./tests/containers/run-matrix.sh              # run all distros
#   ./tests/containers/run-matrix.sh debian12      # run one distro
#   ./tests/containers/run-matrix.sh --build-only  # build images only
#   ./tests/containers/run-matrix.sh --list        # list available distros
#
# The host must support nested podman (rootless or --privileged).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_PREFIX="terok-shield-test"

# Target distros: name -> Containerfile suffix
declare -A DISTROS=(
    [debian12]="debian12"
    [ubuntu2404]="ubuntu2404"
    [debian13]="debian13"
    [fedora43]="fedora43"
    [podman]="podman"
)

# Expected podman versions (for reporting, not enforcement)
declare -A EXPECTED_VERSIONS=(
    [debian12]="4.3.x"
    [ubuntu2404]="4.9.x"
    [debian13]="5.4.x"
    [fedora43]="5.8.x"
    [podman]="latest"
)

usage() {
    echo "Usage: $0 [OPTIONS] [DISTRO...]"
    echo ""
    echo "Options:"
    echo "  --build-only   Build images without running tests"
    echo "  --list         List available distros"
    echo "  --host-only    Run only needs_host_features tests (fast)"
    echo "  -h, --help     Show this help"
    echo ""
    echo "Available distros: ${!DISTROS[*]}"
    return 0
}

build_image() {
    local name="$1"
    local file="$SCRIPT_DIR/Containerfile.${DISTROS[$name]}"
    local image="$IMAGE_PREFIX:$name"

    echo "==> Building $image from $file"
    podman build -t "$image" -f "$file" "$REPO_ROOT"
    return $?
}

run_tests() {
    local name="$1"
    local marker="${2:-needs_host_features}"
    local image="$IMAGE_PREFIX:$name"
    local ctr_name="$IMAGE_PREFIX-$name"

    echo ""
    echo "==> Testing $name (expected podman ${EXPECTED_VERSIONS[$name]})"
    echo "    marker: $marker"
    echo ""

    # Run with --privileged for nested podman/nft support.
    # Mount source as read-only, use a temp venv inside.
    #
    # Three-phase test flow:
    #   1. Run tests that do NOT need hooks (includes hookless error path)
    #   2. Install global hooks via terok-shield setup --user
    #   3. Run tests that need hooks (shielded containers, traffic, restart)
    podman run --rm --name "$ctr_name" \
        --privileged \
        --security-opt label=disable \
        -v "$REPO_ROOT:/src:ro,Z" \
        "$image" \
        bash -c "
            set -e
            echo '--- podman version ---'
            podman --version || echo 'podman not available'
            echo '--- python version ---'
            python3 --version

            # Create a writable workspace
            cp -a /src /workspace
            cd /workspace

            # Install in a venv (use uv if available, else poetry)
            if command -v uv &>/dev/null; then
                uv venv --python 3.12 .venv
                . .venv/bin/activate
                uv pip install poetry
            else
                python3 -m venv .venv
                . .venv/bin/activate
                pip install --quiet pip --upgrade
                pip install --quiet poetry
            fi
            poetry install --with test --quiet 2>&1 | tail -3

            # Track failures across phases so all phases run even if one fails
            rc=0

            # Phase 1: tests without hooks (hookless error path + hook-independent tests)
            echo ''
            echo '--- phase 1: tests without hooks (-m \"$marker and not needs_hooks\") ---'
            poetry run pytest tests/integration/ -m '$marker and not needs_hooks' -v --tb=short 2>&1 || [[ \$? -eq 5 ]] || rc=1
            echo ''
            echo '--- check-environment (before setup) ---'
            poetry run terok-shield check-environment 2>&1 || true

            # Phase 2: install global hooks
            echo ''
            echo '--- phase 2: installing global hooks ---'
            poetry run terok-shield setup --user 2>&1

            echo ''
            echo '--- check-environment (after setup) ---'
            poetry run terok-shield check-environment 2>&1 || true

            # Phase 3: tests that need hooks
            echo ''
            echo '--- phase 3: tests with hooks (-m \"$marker and needs_hooks\") ---'
            poetry run pytest tests/integration/ -m '$marker and needs_hooks' -v --tb=short 2>&1 || [[ \$? -eq 5 ]] || rc=1

            exit \$rc
        "

    local rc=$?
    echo "==> $name: done"
    return $rc
}

# Parse args
BUILD_ONLY=false
LIST_ONLY=false
MARKER="needs_host_features"
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only) BUILD_ONLY=true ;;
        --list) LIST_ONLY=true ;;
        --host-only) MARKER="needs_host_features" ;;
        --podman) MARKER="needs_podman" ;;
        --all-markers) MARKER="" ;;
        -h|--help) usage; exit 0 ;;
        *) TARGETS+=("$1") ;;
    esac
    shift
done

if $LIST_ONLY; then
    for name in "${!DISTROS[@]}"; do
        echo "$name (podman ${EXPECTED_VERSIONS[$name]})"
    done | sort
    exit 0
fi

# Default: all distros
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("${!DISTROS[@]}")
fi

# Validate targets
for t in "${TARGETS[@]}"; do
    if [[ -z "${DISTROS[$t]+x}" ]]; then
        echo "Error: unknown distro '$t'. Available: ${!DISTROS[*]}" >&2
        exit 1
    fi
done

# Build
for t in "${TARGETS[@]}"; do
    build_image "$t"
done

if $BUILD_ONLY; then
    echo "Images built. Use '$0' without --build-only to run tests."
    exit 0
fi

# Run
PASSED=()
FAILED=()

for t in "${TARGETS[@]}"; do
    if run_tests "$t" "$MARKER"; then
        PASSED+=("$t")
    else
        FAILED+=("$t")
    fi
done

# Summary
echo ""
echo "===== Matrix Summary ====="
for t in "${PASSED[@]}"; do
    echo "  PASS: $t (podman ${EXPECTED_VERSIONS[$t]})"
done
for t in "${FAILED[@]}"; do
    echo "  FAIL: $t (podman ${EXPECTED_VERSIONS[$t]})"
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
