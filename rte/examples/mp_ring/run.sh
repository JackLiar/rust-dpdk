#!/usr/bin/env bash
# Run the primary/secondary mbuf round-trip demo.
#
# DPDK multi-process needs shared hugepages and two disjoint lcores. This script
# checks for hugepages, builds the example, starts the primary, waits for it to
# publish the "ping" packet, then runs the secondary and checks both markers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

# `env.sh` appends to variables that may be unset, and cargo usually lives in
# `~/.cargo/bin` on developer machines.
export PATH="$HOME/.cargo/bin:$PATH"
set +u
source env.sh
set -u

if [ "$(awk '/^HugePages_Total:/ {print $2}' /proc/meminfo)" = "0" ]; then
    echo "error: DPDK multi-process needs shared hugepages (HugePages_Total is 0)." >&2
    echo "       run as root: sudo ./dpdk-hugepages.py -p 2M --setup 1G" >&2
    exit 1
fi

RUNTIME_DIR="$(mktemp -d)"
PRIMARY_PID=""

cleanup() {
    if [ -n "$PRIMARY_PID" ]; then
        kill "$PRIMARY_PID" 2>/dev/null || true
    fi

    rm -rf "$RUNTIME_DIR"
}

trap cleanup EXIT

export XDG_RUNTIME_DIR="$RUNTIME_DIR"

cargo build -q -p rte --example mp_ring

BIN="$REPO_ROOT/target/debug/examples/mp_ring"
COMMON=(--file-prefix=mpring -m 256 --no-pci --iova-mode=va)

"$BIN" primary "${COMMON[@]}" -l 0 --proc-type=primary > "$RUNTIME_DIR/primary.log" 2>&1 &
PRIMARY_PID=$!

for _ in $(seq 1 100); do
    if grep -q PRIMARY_READY "$RUNTIME_DIR/primary.log" 2>/dev/null; then
        break
    fi

    if ! kill -0 "$PRIMARY_PID" 2>/dev/null; then
        echo "error: primary exited before becoming ready" >&2
        cat "$RUNTIME_DIR/primary.log" >&2
        exit 1
    fi

    sleep 0.1
done

if ! grep -q PRIMARY_READY "$RUNTIME_DIR/primary.log"; then
    echo "error: primary did not become ready in time" >&2
    cat "$RUNTIME_DIR/primary.log" >&2
    exit 1
fi

set +e
"$BIN" secondary "${COMMON[@]}" -l 1 --proc-type=secondary > "$RUNTIME_DIR/secondary.log" 2>&1
SECONDARY_STATUS=$?
wait "$PRIMARY_PID"
PRIMARY_STATUS=$?
set -e

PRIMARY_PID=""

cat "$RUNTIME_DIR/primary.log"
cat "$RUNTIME_DIR/secondary.log"

if [ "$SECONDARY_STATUS" -ne 0 ] || [ "$PRIMARY_STATUS" -ne 0 ]; then
    echo "error: primary/secondary exited with $PRIMARY_STATUS/$SECONDARY_STATUS" >&2
    exit 1
fi

grep -q PRIMARY_OK "$RUNTIME_DIR/primary.log"
grep -q SECONDARY_OK "$RUNTIME_DIR/secondary.log"

echo "multi-process mbuf ring round trip OK"
