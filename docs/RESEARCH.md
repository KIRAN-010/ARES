# Reproducible vulnerability research demonstration

## Built-in Python experiment

The Research screen mutates four seed inputs for a length-prefixed parser. The first byte declares the payload size; the legacy fixture trusts it. Truncated payloads cause `IndexError`. The minimizer deletes bytes while preserving failure, and the fixed parser checks the declared length before indexing.

The recorded seed makes mutation reproducible. A SHA-256 identifies the minimized input, and the same input is passed to the fixed parser. The result proves a bug in this educational fixture, not an exploit in an external product.

## Native C / AddressSanitizer

```bash
source .venv/bin/activate
python scripts/native_fuzz.py
```

The script compiles only `labs/parser.c`, once with the deliberate missing check and once with `-DFIXED`, using AddressSanitizer (ASan). It tries up to 64 seeded input mutations, checks for a heap-buffer-overflow diagnostic, minimizes a reproducer and confirms the fixed binary rejects it. Builds are placed in a temporary directory and removed. Compilation and execution have timeouts. No uploaded executable or malware is run.

## Optional AFL++ extension in a disposable research VM

Install AFL++ and its compiler toolchain using your VM's package manager. The workflow below applies only to the bundled fixture:

```bash
mkdir -p data/fuzz/seeds
printf '\003abc' > data/fuzz/seeds/valid
afl-clang-fast -g -O1 -fsanitize=address labs/parser.c -o data/fuzz/parser
AFL_USE_ASAN=1 afl-fuzz -m none -i data/fuzz/seeds -o data/fuzz/results -- data/fuzz/parser
```

Stop the experiment with Ctrl+C; inspect crash inputs and reproduce them under ASan. AFL++ is optional and is not invoked by the Helpbot. Its execution, coverage behavior and results are not claimed as tested here. [Official AFL++ documentation](https://aflplus.plus/docs/).

Extending to third-party targets requires explicit authorization, a separate isolated harness, resource limits, corpus management and independent reproduction. Do not point the controller at arbitrary executables and call that sandboxing.
