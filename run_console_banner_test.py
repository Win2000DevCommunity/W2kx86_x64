#!/usr/bin/env python3
"""Launch cmd_shim with its own console; read screen buffer for banner/prompt text."""
from __future__ import annotations

import ctypes as C
import os
import subprocess
import sys
import time

import dbg_fault as df

k32 = C.windll.kernel32

EXE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "build_out7", "cmd_shim.exe")
)
if len(sys.argv) > 1:
    EXE = os.path.abspath(sys.argv[1])


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


def read_console(pid: int) -> str:
    if not k32.AttachConsole(pid):
        return ""
    try:
        h = k32.CreateFileW("CONOUT$", 0xC0000000, 3, None, 3, 0, None)
        if h in (-1, 0xFFFFFFFF):
            return ""
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
        k32.CloseHandle(h)
        return buf.value
    finally:
        k32.FreeConsole()


def main() -> int:
    if not os.path.isfile(EXE):
        print("missing:", EXE)
        return 1
    df.suppress_fault_ui()
    print("exe:", EXE)
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    flags = subprocess.CREATE_NEW_CONSOLE
    p = subprocess.Popen(
        [EXE],
        cwd=os.path.dirname(EXE),
        creationflags=flags,
        startupinfo=si,
    )
    time.sleep(4)
    text = read_console(p.pid)
    alive = p.poll() is None
    if alive:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
    print("alive:", alive)
    print("console capture (%d chars):" % len(text))
    if text:
        print(text[:800])
    low = text.lower()
    ok_banner = "microsoft" in low or "windows" in low or "version" in low
    ok_prompt = "> " in text or ":\\>" in text or "c:\\>" in low
    passed = alive and (ok_banner or ok_prompt)
    if ok_banner:
        print("OK: banner-like text present")
    else:
        print("WARN: no banner text in console buffer")
    if ok_prompt:
        print("OK: prompt-like text present")
    else:
        print("WARN: no prompt in console buffer")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
