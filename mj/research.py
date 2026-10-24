"""Bounded reproducible fuzzing of a built-in educational parser.

Does not load user code or execute uploaded samples. The crash is a Python
IndexError, illustrating an unchecked length field, not a native exploit.
"""
import hashlib
import random


def parse_legacy(data):
    if not data:
        return b""
    size = data[0]
    return bytes(data[i + 1] for i in range(size))


def parse_fixed(data):
    if not data:
        return b""
    size = data[0]
    if size > len(data) - 1:
        raise ValueError("Declared payload exceeds available bytes")
    return data[1:size + 1]


def crashes(data):
    try:
        parse_legacy(data)
    except IndexError:
        return True
    return False


def minimize(data):
    changed = True
    while changed:
        changed = False
        for i in range(len(data)):
            candidate = data[:i] + data[i + 1:]
            if crashes(candidate):
                data = candidate
                changed = True
                break
    return data


def fuzz(seed=42, iterations=256):
    rng = random.Random(seed)
    corpus = [b"", b"\x00", b"\x03abc", b"\x01x"]
    first = None
    count = 0
    for i in range(iterations):
        candidate = bytearray(rng.choice(corpus))
        if candidate and rng.random() < 0.5:
            candidate[rng.randrange(len(candidate))] = rng.randrange(256)
        else:
            candidate.append(rng.randrange(256))
        if crashes(bytes(candidate)):
            count += 1
            if first is None:
                first = bytes(candidate)
    reduced = minimize(first) if first is not None else None
    rejected = False
    if reduced is not None:
        try:
            parse_fixed(reduced)
        except ValueError:
            rejected = True
    return {"harness": "builtin_length_prefixed_parser", "seed": seed, "iterations": iterations,
            "crashes": count, "unique_crash_classes": int(first is not None),
            "minimized_input_hex": reduced.hex() if reduced is not None else None,
            "reproducer_sha256": hashlib.sha256(reduced).hexdigest() if reduced is not None else None,
            "reproduced": reduced is not None and crashes(reduced), "fixed_parser_rejects": rejected,
            "classification": "confirmed_builtin_demo_crash",
            "limitations": "Educational Python parser only; no third-party vulnerability or native exploit is claimed"}
