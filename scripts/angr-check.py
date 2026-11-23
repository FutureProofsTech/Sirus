#!/usr/bin/env python3
"""Bounded angr symbolic-execution probe against a protected artifact.

The probe asks for any input pair whose protected result equals the result of
the reference invocation (7, 3). A timeout or an unsatisfiable return is a
resistance result; a concrete preimage is a break and exits nonzero.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

try:
    import angr
    from angr.claripy import BVS
except ImportError as error:
    print(f"angr unavailable: {error}", file=sys.stderr)
    raise SystemExit(2) from error

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = Path(
    os.environ.get("SIRUS_ANGR_ARTIFACT", str(ROOT / "target" / "redteam" / "protected-a"))
)
TIMEOUT = int(os.environ.get("SIRUS_ANGR_TIMEOUT", "120"))
RETURN_ADDRESS = int(os.environ.get("SIRUS_ANGR_RETURN", "0x4f000000"), 0)


class ProbeTimeout(Exception):
    """Raised by the wall-clock alarm."""


def alarm_handler(_signal: int, _frame: object) -> None:
    raise ProbeTimeout


def reference_output() -> int:
    output = subprocess.check_output(
        [str(ARTIFACT), "7", "3"], text=True, timeout=30
    ).splitlines()
    if not output:
        raise SystemExit("artifact produced no reference output")
    return int(output[0])


def main() -> int:
    if not ARTIFACT.is_file():
        print(f"missing artifact: {ARTIFACT}", file=sys.stderr)
        return 2
    target = reference_output()
    project = angr.Project(str(ARTIFACT), auto_load_libs=False)
    symbols = [
        symbol
        for symbol in project.loader.main_object.symbols
        if "sirus_demo_check" in symbol.name
    ]
    if not symbols:
        print("sirus_demo_check symbol not found", file=sys.stderr)
        return 2
    address = symbols[0].rebased_addr
    first = BVS("input_a", 64)
    second = BVS("input_b", 64)
    state = project.factory.call_state(
        address,
        first,
        second,
        ret_addr=RETURN_ADDRESS,
        cc=project.factory.cc(),
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    manager = project.factory.simgr(state)
    print(
        f"angr {angr.__version__}: symbol={symbols[0].name} "
        f"address={address:#x} target={target} timeout={TIMEOUT}s",
        flush=True,
    )

    def found(candidate: angr.SimState) -> bool:
        if candidate.addr != RETURN_ADDRESS:
            return False
        try:
            return candidate.solver.satisfiable(
                extra_constraints=(candidate.regs.rax == target,)
            )
        except Exception:
            return False

    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(TIMEOUT)
    started = time.monotonic()
    try:
        manager.explore(find=found, num_find=1)
        elapsed = time.monotonic() - started
        if manager.found:
            solution = manager.found[0]
            value_a = solution.solver.eval(first)
            value_b = solution.solver.eval(second)
            value = solution.solver.eval(solution.regs.rax)
            print(
                "FAIL symbolic preimage: "
                f"a={value_a:#x} b={value_b:#x} rax={value:#x} "
                f"elapsed={elapsed:.2f}s",
                flush=True,
            )
            return 1
        print(
            "RESULT symbolic search exhausted: "
            f"found=0 active={len(manager.active)} deadended={len(manager.deadended)} "
            f"elapsed={elapsed:.2f}s",
            flush=True,
        )
        return 0
    except ProbeTimeout:
        elapsed = time.monotonic() - started
        print(
            "PASS symbolic timeout: "
            f"active={len(manager.active)} deadended={len(manager.deadended)} "
            f"errored={len(manager.errored)} elapsed={elapsed:.2f}s",
            flush=True,
        )
        return 0
    except Exception as error:
        print(f"FAIL symbolic probe error: {error}", flush=True)
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
