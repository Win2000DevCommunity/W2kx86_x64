#!/usr/bin/env python3
"""Run cmd_shim /c echo [text] without VS JIT debugger popups."""
import os
import subprocess
import sys

import dbg_fault as df

ROOT = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(ROOT, "..", "win2000_x64", "cmd_shim.exe")

df.suppress_fault_ui()


def main() -> int:
    print("Running with fault UI suppressed (no Visual Studio JIT popup on crash).")
    exe = os.path.abspath(EXE)
    if not os.path.isfile(exe):
        print(f"missing: {exe}")
        print("Rebuild with:")
        print('  python x86_x64.py "...\\cmd.exe" "..\\win2000_x64\\cmd_shim.exe" '
              '--ntdll-ref C:\\Windows\\System32\\ntdll.dll --static-only --win10-test-shim')
        return 1
    cwd = os.path.dirname(exe)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # Default: /c echo test. Override: python run_echo_test.py hello
    text = sys.argv[1] if len(sys.argv) > 1 else "test"
    args = [exe, "/c", "echo", text]
    r = subprocess.run(
        args,
        capture_output=True,
        timeout=30,
        cwd=cwd,
        creationflags=flags,
    )
    ec = r.returncode & 0xFFFFFFFF
    out = r.stdout or b""
    err = r.stderr or b""
    print(f"args: {' '.join(args[1:])}")
    print(f"exit=0x{ec:08X}")
    if out:
        print(f"stdout ({len(out)} bytes): {out[:64]!r}"
              + ("..." if len(out) > 64 else ""))
    if err:
        print(f"stderr: {err!r}")
    try:
        text_out = out.decode("utf-16-le", errors="replace")
    except Exception:
        text_out = out.decode("ascii", errors="replace")
    clean = ec == 0 and text in text_out
    if clean:
        print(f"OK: echo {text!r} passed")
        return 0
    if ec == 0xC0000005:
        print("FAIL: ACCESS_VIOLATION (use: python dbg_root.py --crt ... for details)")
    elif ec == 0xC00000FD:
        print("FAIL: STACK_OVERFLOW")
    elif ec == 0 and clean:
        print(f"FAIL: stdout too long ({len(out)} bytes)")
    else:
        print(f"FAIL: expected exit 0 with {text!r} line on stdout")
    return 1


if __name__ == "__main__":
    sys.exit(main())
