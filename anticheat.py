#!/usr/bin/env python3
"""Javelin Project - Minimal Anti-Cheat guards (Python implementation).

Features:
- Debugger detection (sys.gettrace and platform checks)
- Suspicious process scan
- Optional script self-integrity verification via SHA-256 (JAVELIN_EXPECTED_SHA256)
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import pathlib
import subprocess
import sys
from typing import Iterable, Optional

TAG = "[Javelin AntiCheat] "

EXIT_OK = 0
EXIT_DEBUGGER = 0xDEB
EXIT_BAD_PROCESS = 0xBAD
EXIT_INTEGRITY_FAILED = 0xC2C

SUSPICIOUS_PROCESSES = (
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
)


def compute_file_sha256(path: os.PathLike[str] | str) -> str:
    """Compute the lowercase hex SHA-256 digest of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def verify_script_integrity(
    script_path: Optional[os.PathLike[str] | str] = None,
    expected_sha256: Optional[str] = None,
) -> bool:
    """Verify the running script's SHA-256 against JAVELIN_EXPECTED_SHA256.

    If no expected hash is provided (and JAVELIN_EXPECTED_SHA256 is unset or empty),
    the integrity check is treated as disabled and returns True.
    """
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get("JAVELIN_EXPECTED_SHA256", "")
    ).strip().lower()

    if not expected:
        return True

    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        return False

    target = pathlib.Path(script_path if script_path is not None else __file__).resolve()
    try:
        actual = compute_file_sha256(target)
    except OSError:
        return False

    return hmac.compare_digest(actual, expected)


def check_debugger() -> bool:
    """Detect active Python or native debugger."""
    if sys.gettrace() is not None:
        return True

    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            if kernel32.IsDebuggerPresent() != 0:
                return True
        except Exception:
            pass

    return False


def check_suspicious_processes(
    suspicious_names: Iterable[str] = SUSPICIOUS_PROCESSES,
) -> bool:
    """Scan running processes for known reverse-engineering / cheat tools."""
    lowered = {name.lower() for name in suspicious_names}
    if not lowered:
        return False

    try:
        if sys.platform == "win32":
            proc = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in proc.stdout.splitlines():
                parts = line.split(",")
                if parts:
                    image_name = parts[0].strip('"').lower()
                    if image_name in lowered:
                        return True
        else:
            proc = subprocess.run(
                ["ps", "-eo", "comm"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in proc.stdout.splitlines():
                if line.strip().lower() in lowered:
                    return True
    except Exception:
        return False

    return False


def main(script_path: Optional[os.PathLike[str] | str] = None) -> int:
    print(f"{TAG}starting checks...")

    if check_debugger():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER

    if check_suspicious_processes():
        print(f"{TAG}Suspicious process detected. Exiting.", file=sys.stderr)
        return EXIT_BAD_PROCESS

    if not verify_script_integrity(script_path=script_path):
        print(
            f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.",
            file=sys.stderr,
        )
        return EXIT_INTEGRITY_FAILED

    print(f"{TAG}All clear. Continue.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
