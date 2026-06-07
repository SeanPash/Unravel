#!/usr/bin/env python3
"""
Attack runner for the Causal Reconstruction Engine demo.

Executes the 5-step kill chain defined in atomics.yaml in sequence,
with configurable delay between steps.

Usage:
    python run.py --speed normal     # 30s between steps (default)
    python run.py --speed fast       # 5s between steps (rehearsal)
    python run.py --speed instant    # no delay (CI / smoke test)
    python run.py --step 3           # run a single step
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

SPEED_DELAYS = {
    "normal": 30,
    "fast": 5,
    "instant": 0,
}


def load_config(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def run_command(command: str, step_num: int) -> bool:
    """Run a shell command. Returns True on success, False on failure."""
    cmd = " ".join(command.split())  # normalize whitespace
    print(f"    $ {cmd[:120]}{'...' if len(cmd) > 120 else ''}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines()[:5]:
                print(f"      {line}")
        if result.returncode != 0:
            print(f"    [WARN] step {step_num} exited {result.returncode}", file=sys.stderr)
            if result.stderr.strip():
                print(f"    [WARN] {result.stderr.strip()[:200]}", file=sys.stderr)
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"    [WARN] step {step_num} timed out after 120s", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"    [WARN] step {step_num} failed to launch: {exc}", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute the Causal Reconstruction Engine demo kill chain."
    )
    parser.add_argument(
        "--speed",
        choices=list(SPEED_DELAYS),
        default="normal",
        help="Delay between steps: normal=30s, fast=5s, instant=0s",
    )
    parser.add_argument(
        "--step",
        type=int,
        metavar="N",
        help="Run only step N (1-5). Skips all other steps.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).parent / "atomics.yaml",
        help="Path to atomics.yaml (default: ./atomics.yaml)",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    steps = config["kill_chain"]

    if args.step is not None:
        steps = [s for s in steps if s["step"] == args.step]
        if not steps:
            print(f"[ERROR] step {args.step} not found in {args.config}", file=sys.stderr)
            return 1

    delay = SPEED_DELAYS[args.speed]
    failures = 0

    for i, step in enumerate(steps):
        print(
            f"\n[+] Step {step['step']}/5  {step['technique']}  {step['name']}"
        )
        print(f"    {step['description'].strip()}")

        command = step.get("command")
        if command:
            ok = run_command(command, step["step"])
            if not ok:
                failures += 1
        else:
            print("    (no command defined)")

        if i < len(steps) - 1 and delay > 0:
            print(f"\n    Waiting {delay}s before next step...")
            time.sleep(delay)

    print(f"\n[+] Kill chain complete  ({len(steps)} steps, {failures} failed)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
