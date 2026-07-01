#!/usr/bin/env python3
"""Run cmd_shim with no args; expect interactive session (not instant AV)."""
import os
import subprocess
import sys
import time

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))


def main() -> int:
    df.suppress_fault_ui()
    print("Running with fault UI suppressed (no Visual Studio JIT popup on crash).")
    print("args: (none — double-click / interactive)")
    p = subprocess.Popen(
        [EXE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=os.path.dirname(EXE),
    )
    time.sleep(2)
    if p.poll() is not None:
        ec = p.returncode & 0xFFFFFFFF
        out = p.stdout.read() if p.stdout else b""
        print(f"exit=0x{ec:08X}")
        if out:
            print("stdout:", repr(out[:400]))
        if ec == 0xC0000005:
            print("FAIL: ACCESS_VIOLATION (use: python dbg_root.py --interactive ...)")
            return 1
        if ec != 0x103 and ec != 259:  # STILL_ACTIVE
            print("FAIL: process exited early")
            return 1
    else:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
        print("OK: process still alive after 2s (interactive session)")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
