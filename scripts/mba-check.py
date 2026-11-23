#!/usr/bin/env python3
"""Run real external MBA simplifiers against the sirus MBA corpus.

The corpus is emitted by a test-only hook in `sirus-core`, so these are the
actual post-rewrite expressions rather than hand-written examples.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import z3

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "target" / "mba" / "corpus.tsv"
SIMBA = Path(os.environ.get("SIRUS_SIMBA", "/opt/sirus-tools/SiMBA/src/simplify.py"))
GAMBA = Path(
    os.environ.get("SIRUS_GAMBA", "/opt/sirus-tools/GAMBA/src/simplify_general.py")
)
MBA_BLAST_DIR = Path(
    os.environ.get("SIRUS_MBA_BLAST", "/opt/sirus-tools/MBA-Blast/mba-simplifier")
)
TOOL_TIMEOUT = float(os.environ.get("SIRUS_MBA_TIMEOUT", "20"))


@dataclass
class Case:
    mode: str
    label: str
    expression: str
    ground_truth: str


def generate_corpus() -> list[Case]:
    CORPUS.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["SIRUS_MBA_CORPUS"] = str(CORPUS)
    result = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "sirus-core",
            "mba_audit_corpus",
            "--",
            "--ignored",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("corpus generation failed")
    if not CORPUS.exists():
        raise SystemExit("corpus generation did not create a file")
    cases: list[Case] = []
    lines = CORPUS.read_text().splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("# mode="):
            index += 1
            continue
        fields = dict(part.split("=", 1) for part in line[2:].split())
        if index + 1 >= len(lines):
            raise SystemExit("truncated corpus")
        expression, ground_truth = lines[index + 1].split("\t", 1)
        label = f"{fields.get('depth', '?')}:{fields.get('op', '?')}"
        cases.append(Case(fields.get("mode", "linear"), label, expression, ground_truth))
        index += 2
    return cases


def extract_result(stdout: str) -> str:
    marker = "simplified to "
    if marker not in stdout:
        return ""
    return stdout.rsplit(marker, 1)[1].strip().splitlines()[0].strip()


# A deliberately small parser for the expression subset emitted by the tools.
def to_z3(expression: str) -> z3.ExprRef:
    tree = ast.parse(expression, mode="eval")
    variables = {
        "x": z3.BitVec("x", 64),
        "y": z3.BitVec("y", 64),
        "z": z3.BitVec("z", 64),
    }

    def visit(node: ast.AST) -> z3.ExprRef:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Name):
            if node.id not in variables:
                raise ValueError(f"unsupported variable {node.id}")
            return variables[node.id]
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return z3.BitVecVal(node.value, 64)
        if isinstance(node, ast.UnaryOp):
            value = visit(node.operand)
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.Invert):
                return ~value
            raise ValueError("unsupported unary operation")
        if isinstance(node, ast.BinOp):
            left = visit(node.left)
            right = visit(node.right)
            operations = {
                ast.Add: lambda a, b: a + b,
                ast.Sub: lambda a, b: a - b,
                ast.Mult: lambda a, b: a * b,
                ast.BitAnd: lambda a, b: a & b,
                ast.BitOr: lambda a, b: a | b,
                ast.BitXor: lambda a, b: a ^ b,
                ast.LShift: lambda a, b: a << b,
                ast.RShift: lambda a, b: z3.LShR(a, b),
            }
            operation = operations.get(type(node.op))
            if operation is None:
                raise ValueError("unsupported binary operation")
            return operation(left, right)
        raise ValueError(f"unsupported syntax {type(node).__name__}")

    return visit(tree)


def equivalent(first: str, second: str) -> bool | None:
    try:
        left = to_z3(first)
        right = to_z3(second)
    except (SyntaxError, ValueError):
        return None
    solver = z3.Solver()
    solver.set(timeout=10_000)
    solver.add(left != right)
    answer = solver.check()
    if answer == z3.unsat:
        return True
    if answer == z3.sat:
        return False
    return None


def run_single(tool: str, script: Path, expression: str) -> tuple[str, float, str]:
    start = time.monotonic()
    try:
        result = subprocess.run(
            [sys.executable, str(script), expression],
            text=True,
            capture_output=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "timeout", time.monotonic() - start, ""
    elapsed = time.monotonic() - start
    if result.returncode != 0 or "Could not parse" in result.stdout + result.stderr:
        return "tool-error", elapsed, ""
    output = extract_result(result.stdout)
    if not output:
        return "no-result", elapsed, ""
    return "result", elapsed, output


def mba_blast_cases(cases: list[Case]) -> tuple[int, int]:
    """Run MBA-Blast one case at a time on its parser-supported subset."""
    if not MBA_BLAST_DIR.exists():
        print("MBA-Blast: not installed")
        return 0, 0
    supported = [
        case
        for case in cases
        if case.mode == "linear" and "<<" not in case.expression and ">>" not in case.expression
    ]
    dataset = ROOT / "target" / "mba" / "mba-blast-one.txt"
    dataset.parent.mkdir(parents=True, exist_ok=True)
    output = Path(f"{dataset}.truthtable.search.simplify.txt")
    shim = (
        "import numpy as np, runpy, sys; "
        "np.mat=np.asmatrix; np.int=int; np.float=float; np.bool=bool; "
        f"sys.argv=['truthtable_simplify.py', {str(dataset)!r}]; "
        "runpy.run_path('truthtable_simplify.py', run_name='__main__')"
    )
    verified = 0
    parser_failures = 0
    for case in supported:
        dataset.write_text(f"{strip_outer(case.expression)},{case.ground_truth}\n")
        output.unlink(missing_ok=True)
        try:
            result = subprocess.run(
                [sys.executable, "-c", shim],
                cwd=MBA_BLAST_DIR,
                text=True,
                capture_output=True,
                timeout=TOOL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            parser_failures += 1
            continue
        if result.returncode != 0 or not output.exists():
            parser_failures += 1
            continue
        lines = output.read_text().splitlines()[1:]
        if any(line.rstrip().endswith(",True") for line in lines):
            verified += 1
        else:
            parser_failures += 1
    print(
        f"MBA-Blast: {verified}/{len(supported)} verified; "
        f"{parser_failures} parser/tool failures on its grammar subset"
    )
    return verified, len(supported)

def strip_outer(expression: str) -> str:
    value = expression.strip()
    if not (value.startswith("(") and value.endswith(")")):
        return value
    depth = 0
    for index, character in enumerate(value):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if depth == 0 and index != len(value) - 1:
            return value
    return value[1:-1].strip()


def main() -> int:
    for name, path in (("SiMBA", SIMBA), ("GAMBA", GAMBA)):
        if not path.exists():
            print(f"{name}: missing at {path}")
            return 1
    cases = generate_corpus()
    print(f"generated {len(cases)} actual MBA cases in {CORPUS.relative_to(ROOT)}")

    results: dict[tuple[str, str], list[tuple[Case, str, float, str]]] = {}
    for tool, script in (("SiMBA", SIMBA), ("GAMBA", GAMBA)):
        for case in cases:
            status, elapsed, output = run_single(tool, script, case.expression)
            results.setdefault((tool, case.mode), []).append(
                (case, status, elapsed, output)
            )

    baseline_verified: dict[str, int] = {}
    for tool in ("SiMBA", "GAMBA"):
        rows = results.get((tool, "linear"), [])
        verified = 0
        for case, status, _elapsed, output in rows:
            if status == "result" and equivalent(output, case.ground_truth) is True:
                verified += 1
        baseline_verified[tool] = verified
        print(f"{tool} linear baseline: {verified}/{len(rows)} verified reductions")

    inverse_rows = results.get(("GAMBA", "inverse"), [])
    inverse_failures = sum(
        1 for _case, status, _elapsed, _output in inverse_rows if status != "result"
    )
    print(
        f"GAMBA inverse-only nonlinear corpus: {inverse_failures}/{len(inverse_rows)} "
        "timeouts/tool failures"
    )

    nonlinear_rows = results.get(("GAMBA", "nonlinear"), [])
    nonlinear_failures = sum(
        1 for _case, status, _elapsed, _output in nonlinear_rows if status != "result"
    )
    print(
        f"GAMBA variable-shift nonlinear corpus: {nonlinear_failures}/{len(nonlinear_rows)} "
        "parser failures"
    )

    simba_inverse = results.get(("SiMBA", "inverse"), [])
    simba_verified = sum(
        1
        for case, status, _elapsed, output in simba_inverse
        if status == "result" and equivalent(output, case.ground_truth) is True
    )
    print(
        f"SiMBA inverse-only corpus: {simba_verified}/{len(simba_inverse)} "
        "equivalence-verified reductions (linear-only tool; not a nonlinear claim)"
    )

    blast_verified, blast_total = mba_blast_cases(cases)

    summary = ROOT / "target" / "mba" / "summary.txt"
    summary.write_text(
        "\n".join(
            [
                f"cases={len(cases)}",
                f"simba_linear_verified={baseline_verified.get('SiMBA', 0)}",
                f"gamba_linear_verified={baseline_verified.get('GAMBA', 0)}",
                f"gamba_inverse_timeouts={inverse_failures}/{len(inverse_rows)}",
                f"gamba_nonlinear_parser_failures={nonlinear_failures}/{len(nonlinear_rows)}",
                f"simba_inverse_verified={simba_verified}/{len(simba_inverse)}",
                f"mba_blast_verified={blast_verified}/{blast_total}",
            ]
        )
        + "\n"
    )

    if baseline_verified.get("SiMBA", 0) < 12 or baseline_verified.get("GAMBA", 0) < 12:
        print("FAIL external tools did not reproduce the linear baseline")
        return 1
    if inverse_failures < max(1, len(inverse_rows) // 2):
        print("FAIL GAMBA reduced the inverse-only nonlinear corpus")
        return 1
    if nonlinear_failures < max(1, len(nonlinear_rows) // 2):
        print("FAIL GAMBA parsed the variable-shift nonlinear corpus")
        return 1
    print("PASS external MBA evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
