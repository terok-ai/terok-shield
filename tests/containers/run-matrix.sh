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
SOURCE_MOUNT="/src"
WORKSPACE_DIR="/workspace"
PYTHON_VERSION="3.12"

# Host-side scratch dir each test container writes its observed podman
# version to.  Surfaced after each distro and in the final summary so the
# matrix report shows what was actually exercised, not just what we expected.
RESULTS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/terok-shield-matrix-XXXXXX")"
chmod 0777 "$RESULTS_DIR"
trap 'rm -rf "$RESULTS_DIR"' EXIT

# distro name -> observed podman version (populated by run_tests).
declare -A ACTUAL_VERSIONS=()

# ── Terminal colors (disabled when stdout is not a tty) ──
if [[ -t 1 ]]; then
    C_BOLD='\033[1m'
    C_CYAN='\033[1;36m'
    C_YELLOW='\033[1;33m'
    C_GREEN='\033[1;32m'
    C_RED='\033[1;31m'
    C_DIM='\033[2m'
    C_RESET='\033[0m'
else
    C_BOLD='' C_CYAN='' C_YELLOW='' C_GREEN='' C_RED='' C_DIM='' C_RESET=''
fi

# Target distros: name -> Containerfile suffix
# ``alpine`` is the non-systemd slot (OpenRC/musl) — it proves the stack
# runs with no systemd at all.  See terok-ai/terok#959, #1113.
declare -A DISTROS=(
    [debian12]="debian12"
    [ubuntu2404]="ubuntu2404"
    [ubuntu2604]="ubuntu2604"
    [debian13]="debian13"
    [fedora43]="fedora43"
    [fedora44]="fedora44"
    [podman]="podman"
    [alpine]="alpine"
    [void]="void"
    [mageia]="mageia"
)

# Slots that are non-systemd (OpenRC/runit/musl): the run-time preflight
# hard-fails these if systemd is unexpectedly present.
declare -A NON_SYSTEMD_SLOTS=(
    [alpine]=1
    [void]=1
)

# Expected podman versions — pinned to the exact distro-shipped point
# release.  We do *not* fail on mismatch (a distro update is a normal
# event), only surface a yellow WARNING so a maintainer can refresh
# the pins.  The ``podman`` image rolls with upstream, so it carries
# no expectation — its observed version is reported as-is.
declare -A EXPECTED_VERSIONS=(
    [debian12]="4.3.1"
    [ubuntu2404]="4.9.3"
    [ubuntu2604]="5.7.0"
    [debian13]="5.4.2"
    [fedora43]="5.8.2"
    [fedora44]="5.8.3"
    [podman]="latest"
    [alpine]="5.3.2"
    [void]="latest"
    [mageia]="latest"
)

# Print "expected podman X.Y.Z" for distros with a version pin, or
# "podman latest, version pinned by upstream" for the bare ``podman``
# image.  Used in the ``==> Testing ...`` heading and the ``--list``
# output.
version_expectation() {
    local name="$1"
    local expected="${EXPECTED_VERSIONS[$name]:-}"
    if [[ "$expected" == "latest" ]]; then
        printf 'podman latest, version pinned by upstream'
    else
        printf 'expected podman %s' "$expected"
    fi
}

# Print the parenthesised version summary for ``$name`` after a run.
# Match (or ``latest``): dim ``(podman X.Y.Z)``.
# Mismatch: yellow ``(WARNING: expected podman A, got podman B)``.
# Never fails the run — distro point releases are routine, the warning
# is just a nudge to refresh ``EXPECTED_VERSIONS``.
version_summary() {
    local name="$1"
    local expected="${EXPECTED_VERSIONS[$name]:-}"
    local actual="${ACTUAL_VERSIONS[$name]:-?}"
    if [[ "$expected" == "latest" || "$expected" == "$actual" ]]; then
        printf '%s(podman %s)%s' "$C_DIM" "$actual" "$C_RESET"
    else
        printf '%s(WARNING: expected podman %s, got podman %s)%s' \
            "$C_YELLOW" "$expected" "$actual" "$C_RESET"
    fi
}

# Non-root user baked into each Containerfile (uid 1000).
# The podman image uses its pre-existing 'podman' user.
declare -A TEST_USERS=(
    [debian12]="testrunner"
    [ubuntu2404]="testrunner"
    [ubuntu2604]="testrunner"
    [debian13]="testrunner"
    [fedora43]="testrunner"
    [fedora44]="testrunner"
    [podman]="podman"
    [alpine]="testrunner"
    [void]="testrunner"
    [mageia]="testrunner"
)

usage() {
    echo "Usage: $0 [OPTIONS] [DISTRO...]"
    echo ""
    echo "Options:"
    echo "  --build-only   Build images without running tests"
    echo "  --no-cache     Rebuild images from scratch (ignore layer cache)"
    echo "  --list         List available distros"
    echo "  --unit-only    Run only unit tests (fast)"
    echo "  --integ-only   Run only integration tests"
    echo "  --keep-dangling  Skip the teardown prune of this harness's dangling layers"
    echo "  -h, --help     Show this help"
    echo ""
    echo "Default: install full infrastructure, run unit + integration tests."
    echo ""
    echo "Available distros: ${!DISTROS[*]}"
    return 0
}

warn_keyring() {
    # Warn when the host's containers.conf does not disable kernel keyrings.
    # Matrix runs cycle many containers and can exhaust the per-user 200-key
    # quota, causing misleading "Disk quota exceeded" (EDQUOT) from crun.
    local conf="${CONTAINERS_CONF:-}"
    if [[ -z "$conf" ]]; then
        for candidate in "$HOME/.config/containers/containers.conf" \
                         /etc/containers/containers.conf; do
            [[ -f "$candidate" ]] && conf="$candidate" && break
        done
    fi
    if [[ -z "$conf" ]] || ! grep -qE '^\s*keyring\s*=\s*false' "$conf" 2>/dev/null; then
        echo -e "${C_YELLOW}WARNING: kernel keyring is not disabled in containers.conf"
        echo -e ""
        echo -e "  Matrix tests create many containers and may exhaust the per-user"
        echo -e "  keyring quota (200 keys), causing spurious EDQUOT errors."
        echo -e ""
        echo -e "  Add to ${C_BOLD}~/.config/containers/containers.conf${C_YELLOW}:"
        echo -e ""
        echo -e "    ${C_BOLD}[containers]${C_YELLOW}"
        echo -e "    ${C_BOLD}keyring = false${C_YELLOW}"
        echo -e ""
        echo -e "  See: https://terok-ai.github.io/terok/kernel-keyring/${C_RESET}"
        echo ""
    fi
}

build_image() {
    local name="$1"
    local file="$SCRIPT_DIR/Containerfile.${DISTROS[$name]}"
    local image="$IMAGE_PREFIX:$name"
    local -a build_args=()

    $NO_CACHE && build_args+=(--no-cache)

    echo -e "${C_CYAN}==> Building ${C_BOLD}$image${C_CYAN} from $file${C_RESET}"
    podman build "${build_args[@]}" -t "$image" -f "$file" "$REPO_ROOT"
    return $?
}

run_tests() {
    local name="$1"
    local test_scope="${2:-all}"
    local image="$IMAGE_PREFIX:$name"
    local ctr_name="$IMAGE_PREFIX-$name"
    local test_user="${TEST_USERS[$name]}"

    echo ""
    echo -e "${C_CYAN}==> Testing ${C_BOLD}$name${C_CYAN} ($(version_expectation "$name"))${C_RESET}"
    echo -e "    ${C_DIM}scope: $test_scope, user: $test_user${C_RESET}"
    echo ""

    # The matrix runner is the full-quality environment:
    # install ALL infrastructure, run ALL tests as a rootless user.
    # Privileged mode gives the outer container the capabilities needed
    # for nested podman, but tests run as uid 1000 (rootless podman).
    podman run --rm --replace --name "$ctr_name" \
        -e TERM=xterm \
        --privileged \
        --security-opt label=disable \
        --device /dev/fuse:rw \
        -e container=podman \
        -v "$REPO_ROOT:$SOURCE_MOUNT:ro,Z" \
        -v "$RESULTS_DIR:/results:rw,Z" \
        "$image" \
        bash -c "
            set -e

            # ── Prepare workspace (as root) ──
            cp -a $SOURCE_MOUNT $WORKSPACE_DIR
            chown -R $test_user:$test_user $WORKSPACE_DIR

            # ── Non-systemd proof ──
            # Non-systemd slots (alpine/void) must run on a genuinely
            # systemd-free host; fail loudly if a future base image regresses
            # that.  Other slots just record their init system in the log.
            echo \"--- init system: PID1=\$(cat /proc/1/comm 2>/dev/null || echo unknown) ---\"
            if command -v systemctl >/dev/null 2>&1 || [ -d /run/systemd/system ]; then
                echo \"systemd: present\"
                if [ \"${NON_SYSTEMD_SLOTS[$name]:-}\" = 1 ]; then
                    echo \"FATAL: '$name' is a non-systemd slot but systemd was detected\" >&2
                    exit 1
                fi
            else
                echo \"systemd: absent — non-systemd host confirmed\"
            fi

            # Strip IPv6 zone-ID nameservers — they reference host interfaces
            # (e.g. eno1) that don't exist inside the container, causing dig
            # to reject the entire resolv.conf.  Fixed upstream in podman 5.4+
            # (https://github.com/containers/common/pull/2233).
            # Remove once we drop < 5.4 support.  See #133.
            cp /etc/resolv.conf /tmp/resolv.conf.clean
            grep -v '^nameserver.*%' /tmp/resolv.conf.clean > /etc/resolv.conf

            # ── Run everything as the rootless test user ──
            su - $test_user -c '
                set -e
                export XDG_RUNTIME_DIR=/run/user/\$(id -u)
                export TEROK_MATRIX=1
                # Image-capability contract only: hooks are phase state,
                # appended below once setup has installed them.
                export TEROK_EXPECT=podman,nft,dnsmasq,dig,getent,internet

                cd $WORKSPACE_DIR

                echo \"--- podman version ---\"
                # Capture observed version into the shared /results dir.
                # No single quotes anywhere in this inner block — it is
                # wrapped in a single-quoted su -c argument, so any single
                # quote would close it early.  Parameter expansion only.
                if command -v podman >/dev/null 2>&1; then
                    podman_ver_line=\$(podman --version 2>&1 | head -n1)
                    echo \"\$podman_ver_line\"
                    # podman version 5.8.2 -> 5.8.2
                    echo \"\${podman_ver_line##* }\" > /results/$name.podman-version
                else
                    echo \"podman not available\"
                    : > /results/$name.podman-version
                fi

                echo \"--- rootless podman preflight ---\"
                podman info --format \"podman={{.Version.Version}} storage={{.Store.GraphDriverName}}\" \
                    || { echo \"FATAL: rootless podman not functional\" >&2; exit 1; }

                if command -v uv >/dev/null 2>&1; then
                    uv venv --python $PYTHON_VERSION .venv
                    . .venv/bin/activate
                    uv pip install poetry
                else
                    python${PYTHON_VERSION} -m venv .venv 2>/dev/null \
                        || python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --quiet --upgrade pip
                    pip install --quiet poetry
                fi

                echo \"--- python version ---\"
                python --version
                poetry install --with test --no-interaction
                echo \"--- deps installed ---\"

                # ── Infrastructure setup ──
                echo \"\"
                echo \"--- installing shield hooks ---\"
                poetry run terok-shield setup
                export TEROK_EXPECT=\${TEROK_EXPECT},hooks

                echo \"\"
                echo \"--- check-environment ---\"
                poetry run terok-shield check-environment 2>&1 || true

                # ── Test execution ──
                case \"$test_scope\" in
                    unit)
                        echo \"\"
                        echo \"--- unit tests ---\"
                        poetry run pytest tests/unit/ -v --tb=short
                        ;;
                    integ)
                        echo \"\"
                        echo \"--- integration tests (all markers) ---\"
                        poetry run pytest tests/integration/ -v --tb=short
                        ;;
                    all)
                        _rc=0

                        echo \"\"
                        echo \"--- unit tests ---\"
                        poetry run pytest tests/unit/ -v --tb=short || _rc=\$?

                        echo \"\"
                        echo \"--- integration tests (all markers) ---\"
                        poetry run pytest tests/integration/ -v --tb=short || { _integ_rc=\$?; [ \$_rc -eq 0 ] && _rc=\$_integ_rc; }

                        exit \$_rc
                        ;;
                esac
            '
        "

    local status=$?

    # Pick up what the inner script observed (may be empty if podman
    # was missing or the container died before reaching that step).
    local actual
    actual=$(cat "$RESULTS_DIR/$name.podman-version" 2>/dev/null || true)
    ACTUAL_VERSIONS[$name]="${actual:-?}"

    local vsummary
    vsummary=$(version_summary "$name")
    if [[ $status -eq 0 ]]; then
        echo -e "${C_GREEN}==> $name: PASS${C_RESET} $vsummary"
    else
        echo -e "${C_RED}==> $name: FAIL${C_RESET} $vsummary" >&2
    fi
    return "$status"
}

BUILD_ONLY=false
LIST_ONLY=false
NO_CACHE=false
TEST_SCOPE="all"
KEEP_DANGLING=false
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only) BUILD_ONLY=true ;;
        --no-cache) NO_CACHE=true ;;
        --list) LIST_ONLY=true ;;
        --unit-only)
            [[ "$TEST_SCOPE" != "all" ]] && { echo "Error: --unit-only and --integ-only are mutually exclusive" >&2; exit 1; }
            TEST_SCOPE="unit" ;;
        --integ-only)
            [[ "$TEST_SCOPE" != "all" ]] && { echo "Error: --unit-only and --integ-only are mutually exclusive" >&2; exit 1; }
            TEST_SCOPE="integ" ;;
        --keep-dangling) KEEP_DANGLING=true ;;
        -h|--help) usage; exit 0 ;;
        *) TARGETS+=("$1") ;;
    esac
    shift
done

if $LIST_ONLY; then
    for name in "${!DISTROS[@]}"; do
        echo "$name ($(version_expectation "$name"))"
    done | sort
    exit 0
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("${!DISTROS[@]}")
fi

for target in "${TARGETS[@]}"; do
    if [[ -z "${DISTROS[$target]+x}" ]]; then
        echo -e "${C_RED}Error: unknown distro '$target'. Available: ${!DISTROS[*]}${C_RESET}" >&2
        exit 1
    fi
done

warn_keyring

# A slot whose image fails to build is recorded and reported as FAILED, but
# does NOT abort the whole matrix — so one run surfaces every distro's issues.
declare -A BUILD_FAILED_MAP=()
for target in "${TARGETS[@]}"; do
    if ! build_image "$target"; then
        echo -e "${C_RED}==> Build FAILED for ${C_BOLD}$target${C_RED} — recording and continuing${C_RESET}" >&2
        BUILD_FAILED_MAP[$target]=1
    fi
done

if $BUILD_ONLY; then
    echo -e "${C_GREEN}Images built.${C_RESET} Use '$0' without --build-only to run tests."
    exit 0
fi

PASSED=()
FAILED=()

for target in "${TARGETS[@]}"; do
    if [[ -n "${BUILD_FAILED_MAP[$target]:-}" ]]; then
        echo -e "${C_RED}==> $target: FAIL (image build failed)${C_RESET}" >&2
        FAILED+=("$target")
        continue
    fi
    if run_tests "$target" "$TEST_SCOPE"; then
        PASSED+=("$target")
    else
        FAILED+=("$target")
    fi
done

echo ""
echo -e "${C_BOLD}===== Matrix Summary =====${C_RESET}"
for target in "${PASSED[@]}"; do
    echo -e "  ${C_GREEN}PASS${C_RESET}: $target $(version_summary "$target")"
done
for target in "${FAILED[@]}"; do
    echo -e "  ${C_RED}FAIL${C_RESET}: $target $(version_summary "$target")"
done


# Teardown hygiene: dangling generations of exactly THIS harness's images
# (Containerfile LABEL ownership) are pruned at idle IO priority — small
# per-run increments instead of an hours-long backlog.  Opt out with
# --keep-dangling.
if ! $KEEP_DANGLING; then
    echo ""
    echo -e "${C_DIM}Pruning this harness's dangling image generations (idle io)…${C_RESET}"
    prune=(podman image prune -f --filter "label=io.terok.matrix-test=$IMAGE_PREFIX")
    command -v nice >/dev/null && prune=(nice -n19 "${prune[@]}")
    command -v ionice >/dev/null && prune=(ionice -c3 "${prune[@]}")
    pruned=$("${prune[@]}" | wc -l) || true
    echo -e "${C_DIM}pruned ${pruned:-0} image record(s)${C_RESET}"
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
