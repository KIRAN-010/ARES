"""Compile and test ONLY the bundled educational C harness under ASan.

No arbitrary executable paths, downloaded samples, or shell invocation.
Outputs JSON with reproducible input and fixed-harness validation.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile


def main():
    compiler = shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        raise SystemExit("Install gcc or clang to run the native harness")
    source = Path(__file__).resolve().parents[1] / "labs" / "parser.c"
    env = {**os.environ, "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:symbolize=0"}
    with tempfile.TemporaryDirectory(prefix="mj-harness-") as directory:
        root = Path(directory)
        for name, flags in [("legacy", []), ("fixed", ["-DFIXED"])]:
            subprocess.run([compiler, "-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0",
                            *flags, str(source), "-o", str(root / name)], check=True, timeout=30, capture_output=True)

        def run(name, value):
            return subprocess.run([str(root / name)], input=value, capture_output=True, timeout=2, env=env)

        def is_crash(value):
            return b"heap-buffer-overflow" in run("legacy", value).stderr

        rng = random.Random(42)
        reproducer = None
        for i in range(64):
            candidate = bytes([rng.randrange(2, 256)]) + rng.randbytes(rng.randrange(1, 16))
            if is_crash(candidate):
                reproducer = candidate
                break
        if reproducer is None:
            raise SystemExit("No ASan heap-buffer-overflow reproduced; inspect compiler/runtime support")
        for i in range(len(reproducer) - 1, -1, -1):
            shorter = reproducer[:i] + reproducer[i + 1:]
            if is_crash(shorter):
                reproducer = shorter
        confirmation = run("legacy", reproducer)
        fixed = run("fixed", reproducer)
        result = {"fixture": "labs/parser.c", "seed": 42, "input_hex": reproducer.hex(),
                  "sha256": hashlib.sha256(reproducer).hexdigest(),
                  "asan_confirmed": b"heap-buffer-overflow" in confirmation.stderr,
                  "fixed_rejects_input": fixed.returncode == 2 and b"ERROR: AddressSanitizer" not in fixed.stderr,
                  "sanitizer_excerpt": confirmation.stderr.decode(errors="replace")[:1800]}
        print(json.dumps(result, indent=2))
        if not result["asan_confirmed"] or not result["fixed_rejects_input"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
