"""Run every test suite. Usage: python3 tests/run_all.py"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITES = ["run.py", "test_adversarial.py", "test_filter.py", "test_pass1_regressions.py",
          "test_permissions.py", "test_permissions_v2.py", "test_resolve.py"]

failed = []
for s in SUITES:
    r = subprocess.run([sys.executable, str(HERE / s)], capture_output=True, text=True)
    last = (r.stdout.strip().splitlines() or ["(no output)"])[-1]
    print(f"{'PASS' if r.returncode == 0 else 'FAIL'}  {s:28} {last}")
    if r.returncode != 0:
        failed.append(s)
        print(r.stdout[-2000:], r.stderr[-2000:])
print("\nALL SUITES PASS" if not failed else f"\nFAILED: {', '.join(failed)}")
sys.exit(1 if failed else 0)
