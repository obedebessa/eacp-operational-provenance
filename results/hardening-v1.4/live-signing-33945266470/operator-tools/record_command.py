#!/usr/bin/env python3
"""Retain an explicitly supplied operational command without shell expansion."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
p.add_argument('--cwd', type=Path, required=True)
p.add_argument('--timeout', type=int, default=60)
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
command = a.command[1:] if a.command[:1] == ['--'] else a.command
if not command:
    p.error('a command is required')
a.output.mkdir(parents=True, exist_ok=False)
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
t0 = time.monotonic()
try:
    r = subprocess.run(command, cwd=a.cwd, capture_output=True, timeout=a.timeout)
    code, stdout, stderr = r.returncode, r.stdout, r.stderr
    timed_out = False
except subprocess.TimeoutExpired as exc:
    code, stdout, stderr = 124, exc.stdout or b'', exc.stderr or b''
    timed_out = True
(a.output / 'stdout.txt').write_bytes(stdout)
(a.output / 'stderr.txt').write_bytes(stderr)
record = dict(command=command, cwd=str(a.cwd), started_at=started,
              elapsed_seconds=time.monotonic()-t0, exit_code=code, timed_out=timed_out)
(a.output / 'command.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(record_directory=str(a.output), **record), indent=2))
if len(stdout) <= 3500:
    print(stdout.decode(errors='replace'))
if stderr:
    print(stderr[-2500:].decode(errors='replace'))
raise SystemExit(code)
