#!/usr/bin/env python3
"""Record a bounded reproduction with actual commands, failures and source identity."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build_plan(output: Path, python: str | None = None) -> list[dict]:
    """A fixed plan; callers cannot inject arbitrary shell commands via the CLI."""
    python = python or sys.executable
    commands = [
        ("hardening_tests", ["-m", "unittest", "discover", "-s", "tests/hardening", "-v"]),
        ("profile_tests", ["-m", "unittest", "discover", "-s", "spec/tests", "-v"]),
        ("correlation_smoke", ["experiments/correlation_robustness/correlation_robustness.py",
         "--chains", "24", "--services", "4", "--seeds", "20260905", "--output", str(output / "correlation")]),
        ("index_smoke", ["experiments/index_ablation/index_ablation.py", "--sizes", "1000",
         "--trials", "1", "--services", "10", "--query-samples", "10", "--cold-open-samples", "2",
         "--output", str(output / "index")]),
        ("frozen_index", ["experiments/index_ablation/index_ablation.py", "--verify",
         "experiments/index_ablation/results/reference"]),
        ("frozen_reference", ["experiments/github_actions/summarize_reference_run.py", "--verify"]),
        ("frozen_initial_cohort", ["experiments/github_actions/summarize_cross_version_run_set.py",
         "--root", "experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3",
         "--target-manifest", "experiments/github_actions/kubernetes_targets_v1.3.json", "--verify"]),
        ("frozen_confirmatory_cohort", ["experiments/github_actions/summarize_cross_version_run_set.py",
         "--root", "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3",
         "--target-manifest", "experiments/github_actions/kubernetes_targets_v1.3.json", "--verify"]),
    ]
    return [{"name": name, "command": [python, *arguments]} for name, arguments in commands]


def verify_plan(plan: list[dict], root: Path = ROOT) -> None:
    if sys.version_info < (3, 11):
        raise ValueError("Python 3.11 or newer is required")
    if len({step["name"] for step in plan}) != len(plan):
        raise ValueError("duplicate plan step")
    for step in plan:
        command = step["command"]
        if command[1] != "-m" and not (root / command[1]).is_file():
            raise ValueError(f"missing plan source: {command[1]}")
        if any(Path(argument).name == Path(__file__).name for argument in command[1:]):
            raise ValueError("the reproduction plan must not invoke itself")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                            text=True, check=True, timeout=30)
    return result.stdout.rstrip("\n")


def source_state(root: Path, output: Path) -> dict:
    """Hash checked-out files, including untracked candidate sources; exclude only output."""
    paths = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")
    files = {}
    for relative in sorted(set(path for path in paths if path)):
        path = root / relative
        if path.resolve().is_relative_to(output):
            continue
        if path.is_symlink():
            files[relative] = {"kind": "symlink", "sha256": hashlib.sha256(os.readlink(path).encode()).hexdigest()}
        elif path.is_file():
            files[relative] = {"kind": "file", "sha256": sha256(path)}
        else:
            files[relative] = {"kind": "missing"}
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    return {
        "commit": _git(root, "rev-parse", "HEAD"),
        "commit_tree": _git(root, "rev-parse", "HEAD^{tree}"),
        "dirty": bool(status), "git_status_porcelain": status,
        "source_tree_sha256": hashlib.sha256(encoded).hexdigest(), "files": files,
        "scope": "git-tracked plus nonignored untracked files, excluding this output directory",
    }


def environment_record() -> dict:
    try:
        cryptography = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        cryptography = None
    versions = {}
    for program in ("git", "gh"):
        try:
            result = subprocess.run([program, "--version"], capture_output=True, text=True, timeout=10)
            versions[program] = result.stdout.splitlines()[0] if result.returncode == 0 and result.stdout else None
        except (OSError, subprocess.SubprocessError):
            versions[program] = None
    return {
        "python": platform.python_version(), "python_executable": sys.executable,
        "python_implementation": platform.python_implementation(), "sqlite": sqlite3.sqlite_version,
        "cryptography": cryptography, "system": platform.system(), "release": platform.release(),
        "machine": platform.machine(), "cpu_count": os.cpu_count(),
        "command_versions": versions,
        "environment_values_or_credentials_dumped": False,
    }


def _child_environment() -> dict:
    # Preserve basic runtime/CA configuration, not ambient access/storage/signing keys.
    names = {"PATH", "HOME", "SYSTEMROOT", "USERPROFILE", "TEMP", "TMP", "TMPDIR",
             "LANG", "LC_ALL", "LC_CTYPE", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    result = {name: value for name, value in os.environ.items() if name in names}
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    result["PYTHONUNBUFFERED"] = "1"
    return result


def execute_step(step: dict, *, root: Path, output: Path, timeout_seconds: int) -> dict:
    """Retain output on failure/timeout; kill the spawned process group on POSIX."""
    started = now()
    tick = time.monotonic()
    stdout = output / f"{step['name']}.stdout.txt"
    stderr = output / f"{step['name']}.stderr.txt"
    status, returncode = "failed_to_start", None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        os.chmod(stdout, 0o600)
        os.chmod(stderr, 0o600)
        try:
            process = subprocess.Popen(step["command"], cwd=root, stdout=out, stderr=err,
                                       env=_child_environment(), start_new_session=(os.name == "posix"))
        except OSError:
            err.write(b"Process could not start; inspect installed runtime prerequisites.\n")
        else:
            try:
                returncode = process.wait(timeout=timeout_seconds)
                status = "passed" if returncode == 0 else "failed"
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                status = "timed_out" if isinstance(exc, subprocess.TimeoutExpired) else "interrupted"
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                returncode = process.wait()
    return {
        **step, "cwd": str(root), "started_at": started, "finished_at": now(),
        "elapsed_seconds": time.monotonic() - tick, "timeout_seconds": timeout_seconds,
        "status": status, "returncode": returncode,
        "stdout": stdout.name, "stderr": stderr.name,
        "stdout_sha256": sha256(stdout), "stderr_sha256": sha256(stderr),
    }


def _write_new(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    os.chmod(path, 0o600)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory; existing output is never replaced")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-plan", action="store_true", help="validate and print plan without executing experiments")
    mode.add_argument("--dry-run", action="store_true", help="same nonexecuting behavior as --verify-plan")
    parser.add_argument("--timeout-seconds", type=int, default=300, help="per command, 1..1800 seconds")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.timeout_seconds <= 1800:
            raise ValueError("timeout must be between 1 and 1800 seconds")
        output = args.output.resolve()
        plan = build_plan(output)
        verify_plan(plan)
        if args.verify_plan or args.dry_run:
            print(json.dumps({"status": "plan_validated_not_executed", "plan": plan,
                              "independently_reproduced": False}, indent=2))
            return 0
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output must be a fresh nonexistent directory")
        before = source_state(ROOT, output)
        output.mkdir(mode=0o700, parents=True)
        _write_new(output / "source-before.json", before)
        _write_new(output / "plan.json", {"steps": plan, "environment": environment_record(),
                                         "classification": "executor_self_run"})
        results = []
        for step in plan:
            print(f"Running {step['name']}", flush=True)
            result = execute_step(step, root=ROOT, output=output, timeout_seconds=args.timeout_seconds)
            results.append(result)
            _write_new(output / f"{step['name']}.result.json", result)
            if result["status"] == "interrupted":
                break
        after = source_state(ROOT, output)
        _write_new(output / "source-after.json", after)
        source_changed = (before["source_tree_sha256"] != after["source_tree_sha256"]
                          or before["commit"] != after["commit"])
        passed = len(results) == len(plan) and all(result["status"] == "passed" for result in results)
        summary = {
            "schema": "eacp.hardening-reproduction/1", "classification": "executor_self_run",
            "independently_reproduced": False, "external_executor_identity": None,
            "field_validation": False, "status": "passed" if passed and not source_changed else "failed",
            "source_changed_during_run": source_changed, "steps": results,
            "not_run": [step["name"] for step in plan[len(results):]],
            "claim_boundary": "Descriptive small-run and frozen-evidence checks; no independent or field outcome inferred.",
        }
        _write_new(output / "summary.json", summary)
        print(json.dumps({"status": summary["status"], "summary": str(output / "summary.json")}, indent=2))
        return 0 if summary["status"] == "passed" else 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Reproduction stopped: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
