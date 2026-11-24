#!/usr/bin/env bash
# Reproducible native-vs-protected call-overhead measurement.
set -euo pipefail
cd "$(dirname "$0")/.."

work="target/bench-overhead"
rm -rf "$work"
mkdir -p "$work"

cargo build --release -p sirus-protector >/dev/null
rustc --edition=2021 -C opt-level=2 -C panic=abort -C debuginfo=0 \
    bench/overhead.rs -o "$work/native"

profile="${SIRUS_BENCH_PROFILE:-default}"
mode="${SIRUS_BENCH_MODE:-normal}"
case "$mode" in
    normal) mode_args=() ;;
    hardened) mode_args=(--hardened) ;;
    constant-time) mode_args=(--constant-time --constant-time-passes 64) ;;
    hardened-constant-time) mode_args=(--hardened --constant-time --constant-time-passes 64) ;;
    *) echo "unknown SIRUS_BENCH_MODE: $mode" >&2; exit 2 ;;
esac
case "$profile" in
    default) protect_args=(--profile max) ;;
    balanced) protect_args=(--profile balanced) ;;
    minimal) protect_args=(--profile minimal) ;;
    *) echo "unknown SIRUS_BENCH_PROFILE: $profile" >&2; exit 2 ;;
esac

./target/release/sirus protect \
    --input "$work/native" \
    --output "$work/protected" \
    --function-contains sirus_demo_check \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    "${protect_args[@]}" \
    "${mode_args[@]}" \
    >"$work/protect.out"
chmod +x "$work/protected"

native_n="${SIRUS_BENCH_NATIVE:-2000000}"
protected_n="${SIRUS_BENCH_PROTECTED:-1000}"
runs="${SIRUS_BENCH_RUNS:-7}"

python3 - "$work" "$native_n" "$protected_n" "$runs" <<'PY'
import statistics
import subprocess
import sys
from pathlib import Path

work = Path(sys.argv[1])
native_n = int(sys.argv[2])
protected_n = int(sys.argv[3])
runs = int(sys.argv[4])

def sample(binary, iterations):
    values = []
    for _ in range(runs):
        output = subprocess.check_output(
            [str(binary), str(iterations)], text=True, timeout=120
        ).strip()
        fields = dict(part.split("=", 1) for part in output.split())
        values.append(float(fields["ns_per_call"]))
    return statistics.median(values)

def checksum(binary):
    output = subprocess.check_output(
        [str(binary), "1000"], text=True, timeout=120
    ).strip()
    return dict(part.split("=", 1) for part in output.split())["checksum"]

native_checksum = checksum(work / "native")
protected_checksum = checksum(work / "protected")
if native_checksum != protected_checksum:
    raise SystemExit(
        f"checksum mismatch: native={native_checksum} protected={protected_checksum}"
    )
native = sample(work / "native", native_n)
protected = sample(work / "protected", protected_n)

native_size = (work / "native").stat().st_size
protected_size = (work / "protected").stat().st_size
ratio = protected / native
print(f"native_median_ns_per_call={native:.2f}")
print(f"protected_median_ns_per_call={protected:.2f}")
print(f"overhead_ratio={ratio:.1f}x")
print(f"native_size_bytes={native_size}")
print(f"protected_size_bytes={protected_size}")
print(f"added_size_bytes={protected_size - native_size}")
print(f"checksum={native_checksum}")
PY

printf '%s\n' "== profile=$profile mode=$mode =="
printf '%s\n' "== protector report =="
cat "$work/protect.out"
printf '%s\n' "== size =="
ls -l "$work/native" "$work/protected"
