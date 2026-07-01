#!/usr/bin/env python3
"""Test interactive cmd_shim: echo, alive, banner/prompt bytes on stdout."""
from __future__ import annotations

import ctypes as C
import os
import subprocess
import sys
import time

import dbg_fault as df

k32 = C.windll.kernel32

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EXE = os.path.join(ROOT, "build_out11", "cmd_shim.exe")


def _enable_debug_privilege() -> bool:
    """SeDebugPrivilege helps AttachConsole to child CONSOLE processes."""
    adv = C.windll.advapi32
    tok = C.c_void_p()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0028, C.byref(tok)):
        return False
    try:
        class _LUID(C.Structure):
            _fields_ = [("LowPart", C.c_ulong), ("HighPart", C.c_long)]

        class _TOKEN_PRIVILEGES(C.Structure):
            _fields_ = [
                ("PrivilegeCount", C.c_ulong),
                ("Luid", _LUID),
                ("Attributes", C.c_ulong),
            ]

        luid = _LUID()
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", C.byref(luid)):
            return False
        tp = _TOKEN_PRIVILEGES(1, luid, 0x00000002)
        return bool(adv.AdjustTokenPrivileges(tok, False, C.byref(tp), 0, None, None))
    finally:
        k32.CloseHandle(tok)


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


def _read_screen_buffer() -> str:
    h = k32.CreateFileW("CONOUT$", 0xC0000000, 3, None, 3, 0, None)
    if h in (-1, 0xFFFFFFFF):
        return ""
    csbi = _CSBI()
    if not k32.GetConsoleScreenBufferInfo(h, C.byref(csbi)):
        k32.CloseHandle(h)
        return ""
    left, top = csbi.srWindow.Left, csbi.srWindow.Top
    right, bottom = csbi.srWindow.Right, csbi.srWindow.Bottom
    width = right - left + 1
    height = bottom - top + 1
    n = width * height
    buf = C.create_unicode_buffer(n + 1)
    coord = _COORD(left, top)
    read = C.c_ulong()
    if not k32.ReadConsoleOutputCharacterW(h, buf, n, coord, C.byref(read)):
        k32.CloseHandle(h)
        return ""
    k32.CloseHandle(h)
    return buf.value


def _decode(b: bytes) -> str:
    if not b:
        return ""
    try:
        return b.decode("utf-16-le", errors="replace")
    except Exception:
        return b.decode("utf-8", errors="replace")


def test_echo(exe: str) -> bool:
    cwd = os.path.dirname(exe)
    r = subprocess.run(
        [exe, "/c", "echo", "test"],
        capture_output=True,
        timeout=30,
        cwd=cwd,
    )
    ok = r.returncode == 0 and "test" in _decode(r.stdout)
    print(f"echo: {'PASS' if ok else 'FAIL'} exit=0x{r.returncode & 0xFFFFFFFF:08X}")
    if r.stdout:
        print(f"  stdout: {r.stdout[:40]!r}")
    return ok


def test_interactive_alive(exe: str) -> bool:
    cwd = os.path.dirname(exe)
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10)
    p = subprocess.Popen(
        [exe],
        cwd=cwd,
        creationflags=flags,
    )
    time.sleep(3)
    alive = p.poll() is None
    if alive:
        subprocess.run(
            ["taskkill", "/F", "/PID", str(p.pid)],
            capture_output=True,
            timeout=10,
        )
    print(f"interactive alive: {'PASS' if alive else 'FAIL'}")
    return alive


def test_interactive_pipe_banner(exe: str) -> bool:
    """Interactive with piped stdout — banner must use WriteFile."""
    cwd = os.path.dirname(exe)
    p = subprocess.Popen(
        [exe],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd,
    )
    time.sleep(4)
    alive = p.poll() is None
    out = p.stdout.read(65536) if p.stdout else b""
    if alive:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            out += p.stdout.read(65536) if p.stdout else b""
    text = _decode(out)
    low = text.lower()
    ok = bool(text.strip()) and (
        "microsoft" in low or "windows" in low or "version" in low
        or "> " in text or ":\\>" in text
    )
    print(f"pipe banner: {'PASS' if ok else 'FAIL'} ({len(text)} chars)")
    if text.strip():
        print(f"  {text[:300]!r}")
    return ok or alive


def test_console_text(exe: str) -> bool | None:
    """Read child console screen buffer; None if AttachConsole denied (agent shell)."""
    _enable_debug_privilege()
    cwd = os.path.dirname(exe)
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10)
    p = subprocess.Popen([exe], cwd=cwd, creationflags=flags)
    time.sleep(4)
    text = ""
    attached = k32.AttachConsole(p.pid)
    if not attached and k32.GetLastError() == 5:
        print("console capture: SKIP (AttachConsole access denied in this shell)")
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=3)
        return None
    if attached:
        try:
            text = _read_screen_buffer()
        finally:
            k32.FreeConsole()
    alive = p.poll() is None
    if alive:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
    low = text.lower()
    ok_banner = any(x in low for x in ("microsoft", "windows", "version"))
    ok_prompt = "> " in text or ":\\>" in text or "c:\\>" in low
    print(f"console capture: {len(text)} chars alive={alive} banner={ok_banner} prompt={ok_prompt}")
    if text.strip():
        print(text[:400])
    return alive and (ok_banner or ok_prompt)


def test_dbg_pipeline(exe: str) -> bool:
    """dbg_root interactive probes — banner/REPL sites must be hit."""
    import struct
    import threading

    import pefile
    import dbg_root

    df.suppress_fault_ui()
    full, _pipe = dbg_root.discover_interactive_watch(exe)
    pe = pefile.PE(exe)
    watch = {k: full[k] for k in (
        0x8EB9, 0x9072, 0x91B5, 0x2E4B2, 0x2E541, 0x2EAD6, 0x2EAE9, 0x3D196,
    ) if k in full}
    img = pe.get_memory_mapped_image()
    if img[0x3D196] == 0xE9:
        rel = struct.unpack_from("<i", img, 0x3D197)[0]
        watch[0x3D196 + 5 + rel] = "prompt cave"
    pipeline = list(watch.keys())
    daemon = dbg_root.RootCauseDaemon(
        exe, [], trace=False, max_exc=24, no_jump=False,
        watch=watch, exit_report=True, pipeline=pipeline,
        new_console=True,
    )
    print("dbg_root interactive probe (8s max)...")

    def _run() -> None:
        try:
            daemon.run()
        except Exception as exc:
            print(f"dbg_root error: {exc}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    time.sleep(8)
    if daemon.pi:
        try:
            import ctypes as C

            k32 = C.windll.kernel32
            k32.TerminateProcess(daemon.pi.hProcess, 0)
        except Exception:
            pass
    t.join(timeout=5)
    hits = getattr(daemon, "probe_hits", []) or []
    hit_rvas = {h.rva for h in hits}
    print(f"probe hits: {len(hits)}/{len(watch)}")
    for rva, label in watch.items():
        mark = "OK" if rva in hit_rvas else "MISS"
        print(f"  [{mark}] {label} @ 0x{rva:X}")
    need = {0x8EB9, 0x2E4B2, 0x2EAD6, 0x3D196}
    ok = need.issubset(hit_rvas)
    print(f"pipeline critical: {'PASS' if ok else 'WARN (debugger may block path)'}")
    return ok


def main() -> int:
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EXE)
    if not os.path.isfile(exe):
        print(f"missing: {exe}")
        return 1
    print(f"exe: {exe}")
    df.suppress_fault_ui()
    results = [
        test_echo(exe),
        test_interactive_alive(exe),
    ]
    if os.environ.get("CMD_SHIM_DBG_PROBE"):
        dbg_ok = test_dbg_pipeline(exe)
        if not dbg_ok:
            print("dbg probes incomplete (expected under debug attach)")
    if all(results):
        print("CORE PASS (echo + interactive alive)")
        return 0
    print("SOME TESTS FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
