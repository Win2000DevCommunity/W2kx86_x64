"""Watch first hits of key RVAs under the same tracer as dbg_trace."""
import argparse, ctypes, struct, sys, time
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dbg_trace as DT

WATCH = {
    0x7700: "diamond",
    0x7707: "selfjmp/healed",
    0x1D03C: "helper_caller",
    0x1397C: "helper_add9",
    0x33D21: "longjmp_gate",
    0x33D63: "longjmp_call",
    0x1ADE0: "setjmp_fb40",
}

def run(exe: str, seconds: float = 20.0):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # reuse dbg_trace spawn/step
    args = [exe, "/c", "echo", "w2ktest"]
    # Call into dbg_trace internals lightly by exec-ing modified main logic
    # Simpler: subprocess-style via DT's helpers if any
    print("exe", exe)
    # Import the stepping loop by duplicating minimal parts from dbg_trace.main
    import os
    os.environ.setdefault("PURE", "1")

    # Use CreateProcess + single-step like dbg_trace
    # Easiest path: patch by reading dbg_trace and invoking with a callback
    # For speed, shell out to a one-off inline copy of the critical loop.

    from dbg_trace import (
        DEBUG_PROCESS, DEBUG_ONLY_THIS_PROCESS, CREATE_UNICODE_ENVIRONMENT,
        EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, EXCEPTION_ACCESS_VIOLATION,
        DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, CONTEXT_FULL,
        get_pe_image_base_and_entry, disasm_one, load_rva_map,
    )
    # Fall back: just run dbg_trace and parse - can't get first-hit.
    # Implement minimal watcher here.
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    class EXCEPTION_RECORD(ctypes.Structure):
        pass
    EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wintypes.DWORD),
        ("ExceptionInformation", ctypes.c_ulonglong * 15),
    ]

    class EXCEPTION_DEBUG_INFO(ctypes.Structure):
        _fields_ = [("ExceptionRecord", EXCEPTION_RECORD),
                    ("dwFirstChance", wintypes.DWORD)]

    class DEBUG_EVENT(ctypes.Structure):
        class U(ctypes.Union):
            _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("pad", ctypes.c_byte * 160)]
        _fields_ = [("dwDebugEventCode", wintypes.DWORD),
                    ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD),
                    ("u", U)]

    class CONTEXT(ctypes.Structure):
        _fields_ = [("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
                    ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
                    ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
                    ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
                    ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
                    ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
                    ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
                    ("EFlags", wintypes.DWORD),
                    ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong),
                    ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong),
                    ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
                    ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong),
                    ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong),
                    ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
                    ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong),
                    ("R8", ctypes.c_ulonglong), ("R9", ctypes.c_ulonglong),
                    ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
                    ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong),
                    ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong),
                    ("Rip", ctypes.c_ulonglong),
                    ("rest", ctypes.c_byte * 2000)]

    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = f'"{exe}" /c echo w2ktest'
    ok = k32.CreateProcessW(None, ctypes.c_wchar_p(cmd), None, None, False,
                            0x1, None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        print("CreateProcess failed", ctypes.get_last_error()); return

    base = None
    first = {}
    steps = 0
    t0 = time.time()
    ev = DEBUG_EVENT()
    thr = {}
    CONTEXT_ALL = 0x10001F

    while time.time() - t0 < seconds:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 500):
            continue
        cont = 0x00010002  # DBG_CONTINUE
        code = ev.dwDebugEventCode
        if code == 3:  # CREATE_PROCESS
            base = ev.u.Exception.ExceptionRecord.ExceptionAddress  # wrong - use different
        elif code == 1:  # EXCEPTION
            er = ev.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            if ec in (0x80000003, 0x80000004):  # BP / single-step
                hthr = thr.get(ev.dwThreadId)
                if hthr is None:
                    hthr = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                    thr[ev.dwThreadId] = hthr
                ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
                k32.GetThreadContext(hthr, ctypes.byref(ctx))
                if base is None:
                    # guess from RIP high
                    if ctx.Rip >= 0x80000000 and ctx.Rip < 0x80100000:
                        base = 0x80000000
                if base and base <= ctx.Rip < base + 0x100000:
                    rva = ctx.Rip - base
                    steps += 1
                    for w, name in WATCH.items():
                        if w <= rva < w + 0x20 and name not in first:
                            first[name] = (steps, hex(rva), hex(ctx.Rax), hex(ctx.Rcx))
                            print(f"FIRST {name} @ step {steps} rva={rva:#x} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x}")
                    # keep single-stepping main image
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(hthr, ctypes.byref(ctx))
                if ec == 0xC0000005:
                    print("FAULT", hex(ctx.Rip), "steps", steps, "first", first)
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
                    break
            elif ec == 0xC0000005:
                print("AV steps", steps, "first", first)
        elif code == 5:  # EXIT_PROCESS
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
    else:
        print("TIMEOUT steps", steps, "first", first)
    k32.TerminateProcess(pi.hProcess, 1)
    print("DONE", first)

if __name__ == "__main__":
    run(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 18.0)
