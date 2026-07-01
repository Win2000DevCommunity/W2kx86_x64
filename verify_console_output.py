#!/usr/bin/env python3
"""Launch cmd_shim with its own console; verify banner + prompt on screen."""
from __future__ import annotations

import ctypes as C
import os
import subprocess
import sys
import time

import dbg_fault as df

k32 = C.windll.kernel32
adv = C.windll.advapi32


class _COORD(C.Structure):
    _fields_ = [("X", C.c_short), ("Y", C.c_short)]


class _SMALL_RECT(C.Structure):
    _fields_ = [
        ("Left", C.c_short), ("Top", C.c_short),
        ("Right", C.c_short), ("Bottom", C.c_short),
    ]


class _CSBI(C.Structure):
    _fields_ = [
        ("dwSize", _COORD),
        ("dwCursorPosition", _COORD),
        ("wAttributes", C.c_ushort),
        ("srWindow", _SMALL_RECT),
        ("dwMaximumWindowSize", _COORD),
    ]


def _enable_debug_privilege() -> None:
    tok = C.c_void_p()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0028, C.byref(tok)):
        return
    try:

        class _LUID(C.Structure):
            _fields_ = [("LowPart", C.c_ulong), ("HighPart", C.c_long)]

        class _TP(C.Structure):
            _fields_ = [("PrivilegeCount", C.c_ulong), ("Luid", _LUID), ("Attributes", C.c_ulong)]

        luid = _LUID()
        if adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", C.byref(luid)):
            tp = _TP(1, luid, 2)
            adv.AdjustTokenPrivileges(tok, False, C.byref(tp), 0, None, None)
    finally:
        k32.CloseHandle(tok)


def _read_screen() -> str:
    h = k32.CreateFileW("CONOUT$", 0xC0000000, 3, None, 3, 0, None)
    if h in (-1, 0xFFFFFFFF):
        return ""
    csbi = _CSBI()
    if not k32.GetConsoleScreenBufferInfo(h, C.byref(csbi)):
        k32.CloseHandle(h)
        return ""
    left, top = csbi.srWindow.Left, csbi.srWindow.Top
    right, bottom = csbi.srWindow.Right, csbi.srWindow.Bottom
    n = (right - left + 1) * (bottom - top + 1)
    buf = C.create_unicode_buffer(n + 1)
    coord = _COORD(left, top)
    read = C.c_ulong()
    k32.ReadConsoleOutputCharacterW(h, buf, n, coord, C.byref(read))
    k32.CloseHandle(h)
    return buf.value


def main() -> int:
    df.suppress_fault_ui()
    _enable_debug_privilege()
    exe = os.path.abspath(
        sys.argv[1] if len(sys.argv) > 1
        else os.path.join(os.path.dirname(__file__), "build_out10", "cmd_shim.exe")
    )
    if not os.path.isfile(exe):
        print("missing:", exe)
        return 1
    print("exe:", exe)
    _enable_debug_privilege()
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10)
    cwd = os.path.dirname(exe)
    p = subprocess.Popen([exe], cwd=cwd, creationflags=flags)
    time.sleep(5)
    text = ""
    if k32.AttachConsole(p.pid):
        try:
            text = _read_screen()
        finally:
            k32.FreeConsole()
    else:
        print("AttachConsole failed:", k32.GetLastError())
    alive = p.poll() is None
    if alive:
        subprocess.run(["taskkill", "/F", "/PID", str(p.pid)], capture_output=True, timeout=10)
    low = text.lower()
    ok_banner = "microsoft" in low and "windows" in low
    ok_prompt = "> " in text or ":\\>" in low
    print(f"alive={alive} chars={len(text)} banner={ok_banner} prompt={ok_prompt}")
    if text.strip():
        print("--- screen ---")
        try:
            print(text[:600])
        except UnicodeEncodeError:
            sys.stdout.buffer.write(text[:600].encode("utf-8", errors="replace") + b"\n")
    if ok_banner and ok_prompt:
        print("VERIFY PASS")
        return 0
    print("VERIFY FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
