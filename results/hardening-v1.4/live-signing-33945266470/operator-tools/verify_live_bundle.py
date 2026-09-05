#!/usr/bin/env python3
"""Retain real CLI verification receipts for an independently specified EACP run.

This auxiliary tool does not dispatch, download artifacts, or mutate GitHub. It
uses the supplied archive and bundle; the only network-capable commands verify
under default trust and capture GitHub CLI's official trusted-root material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

REPOSITORY = "obedebessa/eacp-operational-provenance"
WORKFLOW = ".github/workflows/eacp-hardening-v1.4.yml"
SOURCE_REF = "refs/heads/main"
ARCHIVE_NAME = "eacp-hardening-v1.4.tar.gz"
PREDICATE = "https://slsa.dev/provenance/v1"
TIMEOUT_SECONDS = 60


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file() or not path.stat().st_size:
        raise ValueError(f"{label} must be a nonempty regular file, not a symlink")
    return path.resolve()


def write_json(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def copy_new(source: Path, destination: Path) -> None:
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with source.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
        shutil.copyfileobj(incoming, outgoing)


def child_environment(*, offline: bool) -> dict:
    # Do not forward ambient EACP keys, tokens, GitHub debug settings or arbitrary
    # PYTHONPATH. gh may use the user's normal configuration under HOME.
    names = {"PATH", "HOME", "SYSTEMROOT", "USERPROFILE", "TEMP", "TMP", "TMPDIR",
             "LANG", "LC_ALL", "LC_CTYPE", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    environment = {name: value for name, value in os.environ.items() if name in names}
    environment.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", "GH_DEBUG": ""})
    if offline:
        # Defense against HTTP(S) fallback, not a general OS network sandbox.
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            environment[name] = "http://127.0.0.1:9"
        environment.update({"NO_PROXY": "", "no_proxy": ""})
    return environment


def run_receipt(name: str, command: list[str], *, output: Path, cwd: Path,
                phase: str, offline: bool, expected_exit: int) -> dict:
    stdout_path = output / "receipts" / f"{name}.stdout.txt"
    stderr_path = output / "receipts" / f"{name}.stderr.txt"
    started, tick = timestamp(), time.monotonic()
    state, code = "failed_to_start", None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        os.chmod(stdout_path, 0o600)
        os.chmod(stderr_path, 0o600)
        try:
            process = subprocess.Popen(command, cwd=cwd, env=child_environment(offline=offline),
                                       stdout=stdout, stderr=stderr, start_new_session=(os.name == "posix"))
        except OSError:
            stderr.write(b"Command could not start; inspect the selected CLI/runtime.\n")
        else:
            try:
                code = process.wait(timeout=TIMEOUT_SECONDS)
                state = "completed"
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                state = "timed_out" if isinstance(exc, subprocess.TimeoutExpired) else "interrupted"
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass
                code = process.wait()
    receipt = {
        "name": name, "phase": phase, "command": command, "cwd": str(cwd),
        "started_at": started, "finished_at": timestamp(), "elapsed_seconds": time.monotonic() - tick,
        "timeout_seconds": TIMEOUT_SECONDS, "process_state": state, "returncode": code,
        "expected_exit_code": expected_exit, "expectation_met": state == "completed" and code == expected_exit,
        "offline_requested": offline,
        "offline_boundary": "local bundle and captured trusted root; HTTP(S) proxy fallback directed to loopback port 9" if offline else None,
        "stdout": str(stdout_path.relative_to(output)), "stderr": str(stderr_path.relative_to(output)),
        "stdout_sha256": digest(stdout_path), "stderr_sha256": digest(stderr_path),
    }
    write_json(output / "receipts" / f"{name}.json", receipt)
    print(f"{name}: {state}, exit={code}, expected={expected_exit}", flush=True)
    return receipt


def raw_command(archive: Path, bundle: Path, source_sha: str, *, trusted_root: Path | None = None) -> list[str]:
    command = [
        "gh", "attestation", "verify", str(archive), "--hostname", "github.com",
        "--bundle", str(bundle), "--repo", REPOSITORY,
        "--source-digest", source_sha, "--signer-digest", source_sha,
        "--source-ref", SOURCE_REF,
        "--cert-identity", f"https://github.com/{REPOSITORY}/{WORKFLOW}@{SOURCE_REF}",
        "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
        "--predicate-type", PREDICATE, "--deny-self-hosted-runners", "--format", "json",
    ]
    if trusted_root is not None:
        command += ["--custom-trusted-root", str(trusted_root)]
    return command


def wrapper_command(repo_root: Path, archive: Path, bundle: Path, source_sha: str,
                    run_id: int, attempt: int, *, trusted_root: Path | None = None) -> list[str]:
    command = [sys.executable, str(repo_root / "scripts/verify_attestation_v1_4.py"), str(archive),
               "--bundle", str(bundle), "--repository", REPOSITORY, "--source-sha", source_sha,
               "--source-ref", SOURCE_REF, "--run-id", str(run_id), "--run-attempt", str(attempt)]
    if trusted_root is not None:
        command += ["--trusted-root", str(trusted_root)]
    return command


def replace_argument(command: list[str], flag: str, value: str) -> list[str]:
    changed = list(command)
    changed[changed.index(flag) + 1] = value
    return changed


def verified_material(receipt: dict, output: Path) -> dict:
    result = json.loads((output / receipt["stdout"]).read_text())
    if not isinstance(result, list) or len(result) != 1:
        raise ValueError("raw verifier did not return exactly one verification result")
    verified = result[0]["verificationResult"]
    return {"certificate": verified["signature"]["certificate"],
            "statement": verified["statement"], "verified_timestamps": verified["verifiedTimestamps"]}


def checksums(output: Path) -> None:
    lines = [f"{digest(path)}  {path.relative_to(output).as_posix()}\n"
             for path in sorted(output.rglob("*")) if path.is_file() and path != output / "SHA256SUMS"]
    with (output / "SHA256SUMS").open("x", encoding="utf-8") as stream:
        stream.writelines(lines)
    os.chmod(output / "SHA256SUMS", 0o600)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--output-new-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    output, records, created_output = None, [], False
    try:
        if sys.version_info < (3, 11):
            raise ValueError("Python 3.11 or newer is required")
        if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha) or args.run_id <= 0 or args.run_attempt <= 0:
            raise ValueError("supply an independently selected full lowercase SHA, positive run ID and attempt")
        if not shutil.which("gh"):
            raise ValueError("GitHub CLI is required; no verification will be simulated")
        repo_root = args.repo_root.resolve()
        tool_files = [regular(repo_root / relative, "verification source") for relative in
                      ("scripts/verify_attestation_v1_4.py", "eacp_hardening/attestation.py", "eacp_hardening/common.py")]
        original_archive = regular(args.archive, "archive")
        original_bundle = regular(args.bundle, "bundle")
        original_binding = regular(original_archive.parent / "binding.json", "binding sidecar")
        original_checksums = regular(original_archive.parent / "SHA256SUMS", "checksum sidecar")
        if original_binding.stat().st_size > 8192 or original_checksums.stat().st_size > 256:
            raise ValueError("binding/checksum sidecar exceeds its workflow size bound")
        if original_archive.name != ARCHIVE_NAME:
            raise ValueError(f"archive basename must remain {ARCHIVE_NAME}")
        target = args.output_new_directory
        if target.exists() or target.is_symlink():
            raise ValueError("output directory must not already exist")
        output = target.resolve()
        output.mkdir(mode=0o700)
        created_output = True
        for child in ("inputs", "receipts", "negative"):
            (output / child).mkdir(mode=0o700)
        original_inputs = {"archive": original_archive, "bundle": original_bundle,
                           "binding": original_binding, "checksums": original_checksums}
        original_hashes = {name: digest(path) for name, path in original_inputs.items()}
        archive, bundle = output / "inputs" / ARCHIVE_NAME, output / "inputs" / "bundle.jsonl"
        retained_inputs = {"archive": archive, "bundle": bundle,
                           "binding": output / "inputs" / "binding.json",
                           "checksums": output / "inputs" / "archive.SHA256SUMS"}
        for name, source in original_inputs.items():
            copy_new(source, retained_inputs[name])
        if original_hashes != {name: digest(path) for name, path in retained_inputs.items()}:
            raise ValueError("an input changed while copying; retained copies require investigation")
        metadata = {
            "schema": "eacp.live-signing-verification-inputs/1", "created_at": timestamp(),
            "repository": REPOSITORY, "workflow": WORKFLOW, "source_ref": SOURCE_REF,
            "expected_source_sha": args.source_sha, "expected_run_id": args.run_id,
            "expected_run_attempt": args.run_attempt,
            "expectation_origin": "explicit operator arguments, not derived from supplied archive/bundle",
            "original_archive_path": str(original_archive), "original_bundle_path": str(original_bundle),
            "original_sidecar_paths": {"binding": str(original_binding), "checksums": str(original_checksums)},
            "original_sha256": original_hashes,
            "verification_sources_sha256": {str(path.relative_to(repo_root)): digest(path) for path in tool_files},
            "auxiliary_script_sha256": digest(Path(__file__).resolve()),
            "python": platform.python_version(), "python_executable": sys.executable,
            "environment_variables_dumped": False,
        }
        write_json(output / "inputs.json", metadata)

        def run(name, command, *, phase="positive", offline=False, expected_exit=0):
            receipt = run_receipt(name, command, output=output, cwd=repo_root,
                                  phase=phase, offline=offline, expected_exit=expected_exit)
            records.append(receipt)
            return receipt

        run("00-gh-version", ["gh", "--version"], phase="metadata")
        binding_code = (
            "import hashlib,json,sys; from pathlib import Path; "
            "from eacp_hardening.attestation import AttestationPolicy,validate_binding; "
            "from eacp_hardening.common import strict_json; "
            "archive,binding,checksums=map(Path,sys.argv[1:4]); "
            "policy=AttestationPolicy(sys.argv[4],sys.argv[5],sys.argv[6],int(sys.argv[7]),int(sys.argv[8])); "
            "validate_binding(archive,strict_json(binding.read_bytes()),policy); "
            "digest=hashlib.sha256(archive.read_bytes()).hexdigest(); "
            "expected=(digest+'  '+archive.name+'\\n').encode(); "
            "assert checksums.read_bytes()==expected, 'SHA256SUMS does not exactly match actual archive bytes'; "
            "print(json.dumps({'binding_consistency_passed':True,'sha256sums_consistency_passed':True,"
            "'archive_sha256':digest,'cryptographic_verification':False}))"
        )
        binding_receipt = run("00b-binding-and-checksum-consistency", [sys.executable, "-c", binding_code,
            str(archive), str(retained_inputs["binding"]), str(retained_inputs["checksums"]),
            REPOSITORY, args.source_sha, SOURCE_REF, str(args.run_id), str(args.run_attempt)], phase="consistency")
        raw_default = run("01-gh-default-trust", raw_command(archive, bundle, args.source_sha))
        wrapper_default = run("02-wrapper-default-trust", wrapper_command(
            repo_root, archive, bundle, args.source_sha, args.run_id, args.run_attempt))
        captured = run("03-capture-official-trusted-root", ["gh", "attestation", "trusted-root", "--hostname", "github.com"])
        root_path = output / "inputs" / "trusted_root.jsonl"
        roots_captured = captured["expectation_met"] and (output / captured["stdout"]).stat().st_size > 0
        material_matches, root_sha256 = False, None
        positive_records = [raw_default, wrapper_default, captured]
        if roots_captured:
            copy_new(output / captured["stdout"], root_path)
            root_sha256 = digest(root_path)
            raw_offline = run("04-gh-captured-root-offline", raw_command(
                archive, bundle, args.source_sha, trusted_root=root_path), offline=True)
            wrapper_offline = run("05-wrapper-captured-root-offline", wrapper_command(
                repo_root, archive, bundle, args.source_sha, args.run_id, args.run_attempt,
                trusted_root=root_path), offline=True)
            positive_records += [raw_offline, wrapper_offline]
            if raw_default["expectation_met"] and raw_offline["expectation_met"]:
                material_matches = verified_material(raw_default, output) == verified_material(raw_offline, output)
        positive_passed = (len(positive_records) == 5 and all(record["expectation_met"] for record in positive_records)
                           and material_matches and binding_receipt["expectation_met"])

        negatives = []
        if positive_passed:
            altered_root = output / "negative" / "altered-archive"
            altered_root.mkdir(mode=0o700)
            altered_archive = altered_root / ARCHIVE_NAME
            copy_new(archive, altered_archive)
            with altered_archive.open("r+b") as stream:
                first = stream.read(1)
                stream.seek(0)
                stream.write(bytes([first[0] ^ 1]))
            write_json(output / "negative" / "altered-archive-change.json", {
                "change": "toggle one bit in byte zero of a retained copy; original preserved",
                "original_sha256": digest(archive), "altered_sha256": digest(altered_archive),
            })
            baseline = raw_command(archive, bundle, args.source_sha, trusted_root=root_path)
            wrong_sha = "0" * 40 if args.source_sha != "0" * 40 else "1" * 40
            wrong_signer = f"https://github.com/{REPOSITORY}/.github/workflows/not-approved.yml@{SOURCE_REF}"
            plans = [
                ("06-negative-altered-archive-gh", raw_command(altered_archive, bundle, args.source_sha, trusted_root=root_path)),
                ("07-negative-altered-archive-wrapper", wrapper_command(repo_root, altered_archive, bundle, args.source_sha,
                                                                      args.run_id, args.run_attempt, trusted_root=root_path)),
                ("08-negative-wrong-sha-wrapper", wrapper_command(repo_root, archive, bundle, wrong_sha,
                                                                 args.run_id, args.run_attempt, trusted_root=root_path)),
                ("09-negative-wrong-run-wrapper", wrapper_command(repo_root, archive, bundle, args.source_sha,
                                                                 args.run_id + 1, args.run_attempt, trusted_root=root_path)),
                ("10-negative-wrong-signer-gh", replace_argument(baseline, "--cert-identity", wrong_signer)),
                ("11-negative-wrong-ref-gh", replace_argument(baseline, "--source-ref", "refs/heads/not-approved")),
            ]
            for name, command in plans:
                negatives.append(run(name, command, phase="negative", offline=True, expected_exit=1))

        input_unchanged = (original_hashes == {name: digest(path) for name, path in original_inputs.items()}
                           == {name: digest(path) for name, path in retained_inputs.items()})
        tools_unchanged = metadata["verification_sources_sha256"] == {
            str(path.relative_to(repo_root)): digest(path) for path in tool_files}
        negative_passed = len(negatives) == 6 and all(record["expectation_met"] for record in negatives)
        passed = positive_passed and negative_passed and input_unchanged and tools_unchanged
        summary = {
            "schema": "eacp.live-signing-verification/1", "status": "passed" if passed else "failed",
            "positive_verifications_passed": positive_passed,
            "binding_and_checksum_consistency_passed": binding_receipt["expectation_met"],
            "archive_sha256": original_hashes["archive"], "bundle_sha256": original_hashes["bundle"],
            "default_and_offline_verified_material_match": material_matches,
            "captured_trusted_root_sha256": root_sha256,
            "negative_checks_expected": 6, "negative_checks_executed": len(negatives),
            "negative_expected_exit_codes_observed": negative_passed,
            "negative_results_require_review_of_retained_error_messages": True,
            "negative_skip_reason": None if positive_passed else "positive verification baseline was not established",
            "original_inputs_and_retained_copies_unchanged": input_unchanged,
            "verification_sources_unchanged": tools_unchanged,
            "expected_policy": {"repository": REPOSITORY, "source_sha": args.source_sha,
                                "source_ref": SOURCE_REF, "run_id": args.run_id, "run_attempt": args.run_attempt},
            "records": records, "classification": "executor_self_run",
            "independent_execution": False, "upstream_event_truth_verified": False,
            "field_validation": False, "automatic_SLSA_level_claim": None,
            "receipt_integrity": "Unsigned SHA-256 manifest; not independent evidence of who executed this tool.",
            "claim_boundary": "Real verification of supplied archive bytes against the explicitly selected workflow/run policy; no authenticity of upstream event semantics or independent third-party execution inferred.",
        }
        write_json(output / "summary.json", summary)
        checksums(output)
        print(json.dumps({"status": summary["status"], "summary": str(output / "summary.json")}, indent=2))
        return 0 if passed else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        if created_output and output is not None and output.is_dir():
            summary = {"schema": "eacp.live-signing-verification/1", "status": "failed",
                       "failure": str(exc), "records": records,
                       "classification": "executor_self_run", "independent_execution": False,
                       "upstream_event_truth_verified": False, "field_validation": False}
            if not (output / "summary.json").exists():
                write_json(output / "summary.json", summary)
            if not (output / "SHA256SUMS").exists():
                checksums(output)
        print(f"Live verification stopped: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
