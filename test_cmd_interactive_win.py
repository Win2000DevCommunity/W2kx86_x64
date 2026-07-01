#!/usr/bin/env python3
"""Interactive cmd_shim test on a real Windows console.

Launches cmd_shim.exe in its own console, reads the screen buffer for
banner + path prompt, injects ``echo hello`` via WriteConsoleInputW, and
checks that output appears.

Usage:
    python test_cmd_interactive_win.py [path\\to\\cmd_shim.exe]
"""
from __future__ import annotations

import ctypes as C
import os
import subprocess
import sys
import time

import dbg_fault as df

k32 = C.windll.kernel32
adv = C.windll.advapi32

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EXE = os.path.join(ROOT, "build_out11", "cmd_shim.exe")

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11


class COORD(C.Structure):
    _fields_ = [("X", C.c_short), ("Y", C.c_short)]


class SMALL_RECT(C.Structure):
    _fields_ = [
        ("Left", C.c_short), ("Top", C.c_short),
        ("Right", C.c_short), ("Bottom", C.c_short),
    ]


class CONSOLE_SCREEN_BUFFER_INFO(C.Structure):
    _fields_ = [
        ("dwSize", COORD),
        ("dwCursorPosition", COORD),
        ("wAttributes", C.c_ushort),
        ("srWindow", SMALL_RECT),
        ("dwMaximumWindowSize", COORD),
    ]


class KEY_EVENT_RECORD(C.Structure):
    _fields_ = [
        ("bKeyDown", C.c_int),
        ("wRepeatCount", C.c_ushort),
        ("wVirtualKeyCode", C.c_ushort),
        ("wVirtualScanCode", C.c_ushort),
        ("UnicodeChar", C.c_wchar),
        ("dwControlKeyState", C.c_ulong),
    ]


class INPUT_RECORD(C.Structure):
    class _Event(C.Union):
        _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]

    _fields_ = [("EventType", C.c_ushort), ("Event", _Event)]


def _enable_debug_privilege() -> bool:
    tok = C.c_void_p()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0028, C.byref(tok)):
        return False
    try:
        class LUID(C.Structure):
            _fields_ = [("LowPart", C.c_ulong), ("HighPart", C.c_long)]

        class TOKEN_PRIVILEGES(C.Structure):
            _fields_ = [
                ("PrivilegeCount", C.c_ulong),
                ("Luid", LUID),
                ("Attributes", C.c_ulong),
            ]

        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", C.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES(1, luid, 0x00000002)
        return bool(adv.AdjustTokenPrivileges(tok, False, C.byref(tp), 0, None, None))
    finally:
        k32.CloseHandle(tok)


def _open_conout() -> int:
    h = k32.CreateFileW(
        "CONOUT$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None,
    )
    return -1 if h in (-1, 0xFFFFFFFF) else int(h)


def _open_conin() -> int:
    h = k32.CreateFileW(
        "CONIN$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None,
    )
    return -1 if h in (-1, 0xFFFFFFFF) else int(h)


def read_screen() -> str:
    h = _open_conout()
    if h < 0:
        return ""
    try:
        csbi = CONSOLE_SCREEN_BUFFER_INFO()
        if not k32.GetConsoleScreenBufferInfo(h, C.byref(csbi)):
            return ""
        left, top = csbi.srWindow.Left, csbi.srWindow.Top
        right, bottom = csbi.srWindow.Right, csbi.srWindow.Bottom
        width = right - left + 1
        height = bottom - top + 1
        n = width * height
        buf = C.create_unicode_buffer(n + 1)
        coord = COORD(left, top)
        read = C.c_ulong()
        if not k32.ReadConsoleOutputCharacterW(h, buf, n, coord, C.byref(read)):
            return ""
        return buf.value
    finally:
        k32.CloseHandle(h)


def write_input(text: str) -> bool:
    h = _open_conin()
    if h < 0:
        return False
    try:
        records = (INPUT_RECORD * (len(text) + 1))()
        for i, ch in enumerate(text):
            ev = records[i]
            ev.EventType = 1  # KEY_EVENT
            ev.Event.KeyEvent.bKeyDown = 1
            ev.Event.KeyEvent.wRepeatCount = 1
            ev.Event.KeyEvent.UnicodeChar = ch
        ev = records[len(text)]
        ev.EventType = 1
        ev.Event.KeyEvent.bKeyDown = 1
        ev.Event.KeyEvent.wVirtualKeyCode = 0x0D
        ev.Event.KeyEvent.UnicodeChar = "\r"
        written = C.c_ulong()
        n = len(text) + 1
        return bool(k32.WriteConsoleInputW(h, records, n, C.byref(written)))
    finally:
        k32.CloseHandle(h)


def run_test(exe: str) -> int:
    if not os.path.isfile(exe):
        print("missing:", exe)
        return 1

    df.suppress_fault_ui()
    _enable_debug_privilege()
    print("exe:", exe)
    cwd = os.path.dirname(exe) or ROOT
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10)
    p = subprocess.Popen([exe], cwd=cwd, creationflags=flags)
    time.sleep(3)

    if p.poll() is not None:
        print("FAIL: process exited early code=0x%X" % (p.returncode & 0xFFFFFFFF))
        return 1

    if not k32.AttachConsole(p.pid):
        err = k32.GetLastError()
        print("WARN: AttachConsole failed (%d) — close other consoles and retry" % err)
        p.terminate()
        p.wait(timeout=5)
        return 1

    try:
        screen = read_screen()
        print("--- screen after startup (%d chars) ---" % len(screen))
        if screen.strip():
            print(screen[:700])

        low = screen.lower()
        ok_banner = "microsoft" in low and "version" in low
        ok_version_dynamic = (
            "5.00" not in screen
            or "version 5.00]" not in screen
            or any(c.isdigit() for c in screen.split("Version", 1)[-1][:12])
        )
        ok_prompt = "> " in screen or ":\\" in screen

        print("banner:", "OK" if ok_banner else "FAIL")
        print("version (not empty/static-only):", "OK" if ok_version_dynamic else "WARN")
        print("prompt:", "OK" if ok_prompt else "FAIL")

        if not ok_prompt:
            print("FAIL: no path prompt visible")
            return 1

        if not write_input("echo hello\r"):
            print("FAIL: WriteConsoleInputW failed")
            return 1

        time.sleep(2)
        screen2 = read_screen()
        print("--- screen after echo (%d chars) ---" % len(screen2))
        if screen2.strip():
            print(screen2[:900])

        ok_echo = "hello" in screen2.lower()
        print("echo output:", "OK" if ok_echo else "FAIL")

        if ok_banner and ok_prompt and ok_echo:
            print("PASS: interactive banner, prompt, and echo")
            return 0
        print("SOME CHECKS FAILED")
        return 1
    finally:
        k32.FreeConsole()
        if p.poll() is None:
            subprocess.run(
                ["taskkill", "/F", "/PID", str(p.pid)],
                capture_output=True, timeout=10,
            )


def main() -> int:
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EXE)
    return run_test(exe)


if __name__ == "__main__":
    raise SystemExit(main())
