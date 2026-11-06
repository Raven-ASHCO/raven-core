#!/usr/bin/env python3
"""The release gate evidence of .github/workflows/raven-serverless.yml
(security review 2026-11, DEP-2).

docs/EVIDENCE.md and docs/SECURITY_REVIEW_SCOPE.md say CI proves, on Linux,
macOS and Windows, that every lab switch is inert and every production flag
holds its pinned value in a release build. This checks the workflow so that
stays true:

  1. the RustSec audit (audit_active_dependencies.py) runs in a job of its
     own with no other run step, so an advisory never skips a gate step;
  2. the Linux, macOS and Windows jobs each run both release inert test sets
     (node/scripts/release_inert_tests.sh switches and pinned);
  3. every release gate step runs with if: ${{ !cancelled() }}, so a failed
     step before it does not skip it.

The workflow is read line by line (GitHub layout: jobs two spaces in, steps
six), so no YAML library is needed; shell comments in run blocks do not
count as running anything.

  check_ci_release_gates.py [--workflow FILE]
  check_ci_release_gates.py --self-test

Exit 0 when every check passes, 1 when one fails.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "raven-serverless.yml"
OS_JOBS = ("rust-linux", "rust-macos", "rust-windows")
AUDIT = "audit_active_dependencies.py"
INERT_RUNS = ("release_inert_tests.sh switches", "release_inert_tests.sh pinned")
# A step whose run text holds one of these is a release gate step.
GATE_MARKERS = INERT_RUNS + (
    "sqlcipher_release_feature_audit.sh",
    "release_tool_feature_audit.sh",
    "unsafe-demo-crypto is forbidden in release builds",
    "the shipped release build is not warning-free",
)
JOB_LINE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_LINE = re.compile(r"^      - (.*)$")


class Step:
    def __init__(self, job: str, first: str):
        self.job = job
        self.lines: List[str] = [" " * 8 + first]

    def key(self, name: str) -> str:
        """A step key at the step level (eight spaces in), or an empty string."""
        for line in self.lines:
            match = re.match(rf"^ {{8}}{name}:\s*(.*)$", line)
            if match:
                return match.group(1).strip()
        return ""

    @property
    def name(self) -> str:
        return self.key("name") or self.key("uses") or "(a step without a name)"

    @property
    def text(self) -> str:
        """What the step runs and says, shell comments left out."""
        return "\n".join(line for line in self.lines if not line.lstrip().startswith("#"))

    def runs(self, marker: str) -> bool:
        return marker in self.text

    def survives_failures(self) -> bool:
        condition = self.key("if").replace(" ", "")
        return condition in ("${{!cancelled()}}", "!cancelled()")


def parse(text: str) -> Dict[str, List[Step]]:
    jobs: Dict[str, List[Step]] = {}
    in_jobs = False
    job = None
    step = None
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" ") and not line.startswith("#"):
            in_jobs = False
            continue
        match = JOB_LINE.match(line)
        if match:
            job = match.group(1)
            jobs[job] = []
            step = None
            continue
        if job is None:
            continue
        match = STEP_LINE.match(line)
        if match:
            step = Step(job, match.group(1))
            jobs[job].append(step)
            continue
        indent = len(line) - len(line.lstrip())
        if step is not None and line.strip() and indent < 8 and not line.lstrip().startswith("#"):
            step = None
            continue
        if step is not None and line.strip():
            step.lines.append(line)
    return jobs


def problems_in(text: str) -> List[str]:
    jobs = parse(text)
    problems = []
    audit_jobs = [job for job, steps in jobs.items() if any(step.runs(AUDIT) for step in steps)]
    if len(audit_jobs) != 1:
        problems.append(f"the RustSec audit ({AUDIT}) must run in exactly one job, not {len(audit_jobs)}")
    for job in audit_jobs:
        run_steps = [step for step in jobs[job] if step.key("run") or any("run: |" in line for line in step.lines)]
        if job in OS_JOBS or len(run_steps) != 1:
            problems.append(
                f"{job}: the RustSec audit must run in a job of its own (no other run step), "
                f"so an advisory never skips a gate step; it has {len(run_steps)} run steps"
            )
    for job in OS_JOBS:
        if job not in jobs:
            problems.append(f"{job}: the job is missing")
            continue
        for run in INERT_RUNS:
            if not any(step.runs(run) for step in jobs[job]):
                problems.append(f"{job}: no step runs {run}")
    for job, steps in jobs.items():
        for step in steps:
            marker = next((m for m in GATE_MARKERS if step.runs(m)), None)
            if marker is not None and not step.survives_failures():
                problems.append(
                    f"{job}: the release gate step \"{step.name}\" ({marker}) needs "
                    "if: ${{ !cancelled() }} so a failed step before it does not skip it"
                )
    return problems


def sample(audit_in_linux: bool = False, extra_audit_step: bool = False, windows_pinned: bool = True,
           inert_if: str = "${{ !cancelled() }}", gate_if: str = "${{ !cancelled() }}",
           commented_switches: bool = False) -> str:
    """A small workflow in the layout of raven-serverless.yml, with one planted fault at a time."""
    audit_step = (
        "      - name: RustSec active dependency audit\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          python3 scripts/audit_active_dependencies.py\n"
    )
    text = "name: sample\non:\n  push:\n\njobs:\n"
    if not audit_in_linux:
        text += (
            "  # The audit, alone.\n"
            "  rustsec-audit:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@0000000000000000000000000000000000000000 # v4\n" + audit_step
        )
        if extra_audit_step:
            text += "      - name: also a test\n        run: cargo test --locked\n"
    for job in OS_JOBS:
        text += f"\n  {job}:\n    runs-on: some-runner\n    steps:\n"
        text += "      - uses: actions/checkout@0000000000000000000000000000000000000000 # v4\n"
        if audit_in_linux and job == "rust-linux":
            text += audit_step
        text += "      - name: test\n        run: cargo test --locked\n"
        switches = "bash scripts/release_inert_tests.sh switches"
        if commented_switches and job == "rust-windows":
            switches = "|\n          # bash scripts/release_inert_tests.sh switches\n          true"
        text += f"      - name: inert\n        if: {inert_if}\n        shell: bash\n        run: {switches}\n"
        if windows_pinned or job != "rust-windows":
            text += (
                "      # The pinned values.\n"
                "      - name: pinned\n        if: ${{ !cancelled() }}\n"
                "        run: bash scripts/release_inert_tests.sh pinned\n"
            )
        if job == "rust-linux":
            text += f"      - name: SQLCipher gate\n        if: {gate_if}\n        run: bash scripts/sqlcipher_release_feature_audit.sh\n"
    text += "\n  later-job:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo done\n"
    return text


def self_test() -> List[str]:
    failures = []
    if problems_in(sample()):
        failures.append(f"a correct layout must pass, got {problems_in(sample())}")
    planted = {
        "the audit inside the Linux job": sample(audit_in_linux=True),
        "another run step in the audit job": sample(extra_audit_step=True),
        "no pinned run on Windows": sample(windows_pinned=False),
        "an inert step without !cancelled()": sample(inert_if="success()"),
        "a gate step without !cancelled()": sample(gate_if=""),
        "the switches run only in a shell comment on Windows": sample(commented_switches=True),
    }
    for name, text in planted.items():
        if not problems_in(text):
            failures.append(f"{name} was not caught")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Checks that the release gate steps of raven-serverless.yml run on every OS and "
        "that the RustSec audit cannot skip them."
    )
    parser.add_argument("--workflow", type=Path, default=WORKFLOW, help="the workflow file to check")
    parser.add_argument("--self-test", action="store_true", help="check that planted faults are caught")
    args = parser.parse_args()
    if args.self_test:
        failures = self_test()
        for failure in failures:
            print(f"FAIL: self test: {failure}", file=sys.stderr)
        if failures:
            return 1
        print("PASS: self test: a correct layout passes and 6 planted faults are caught")
        return 0
    try:
        text = args.workflow.read_text(encoding="utf-8")
    except OSError as error:
        print(f"FAIL: cannot read {args.workflow}: {error}", file=sys.stderr)
        return 1
    problems = problems_in(text)
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(
        "PASS: the RustSec audit runs in a job of its own, and the Linux, macOS and Windows jobs "
        "each run both release inert test sets in steps that survive an earlier failure"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
