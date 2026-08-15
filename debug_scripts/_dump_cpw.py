#!/usr/bin/env python3
"""Dump CreateProcessW context at main+0x8E02."""
import os
import struct
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))


def read_wstr(proc, addr: int, max_chars: int = 260) -> str:
    if not addr:
        return "<null>"
    raw = df.read_process_mem(proc, addr, max_chars * 2)
    out = []
    for i in range(0, len(raw) - 1, 2):
        ch = struct.unpack_from("<H", raw, i)[0]
        if ch == 0:
            break
        out.append(chr(ch) if ch < 128 else "?")
    return "".join(out) or "<empty>"


def main():
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(
        EXE, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    base = None
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ctx = df.get_thread_context(pi.hThread)
            rva = (er.ExceptionAddress or 0) - base if base else 0
            if rva == 0x8E02:
                rbp = ctx.Rbp
                print(f"RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RDI={ctx.Rdi:#x}")
                si_blob = df.read_process_mem(pi.hProcess, rbp - 0x130, 0x68)
                cb = struct.unpack_from("<I", si_blob, 0)[0]
                print(f"STARTUPINFO.cb={cb:#x} at rbp-130={rbp - 0x130:#x}")
                pi_blob = df.read_process_mem(pi.hProcess, rbp - 0x120, 0x18)
                print(f"PROCESS_INFORMATION at rbp-120={rbp - 0x120:#x}: {pi_blob.hex()}")
                for name, off in [("cmdline rbp+18", 0x18), ("cmdline rbp+10", 0x10)]:
                    p = struct.unpack_from("<Q", df.read_process_mem(pi.hProcess, rbp + off, 8))[0]
                    print(f"  {name} -> {p:#x} {read_wstr(pi.hProcess, p)!r}")
                path_ptr = struct.unpack_from("<Q", df.read_process_mem(pi.hProcess, rbp - 0x130 + 0x60, 8))[0] if len(si_blob) >= 0x68 else 0
                # scan stack for pointer-like args
                st = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x100)
                print("stack top:")
                for i in range(0, 0x80, 8):
                    v = struct.unpack_from("<Q", st, i)[0]
                    extra = ""
                    if 0x10000 < v < 0x7fffffffffff:
                        s = read_wstr(pi.hProcess, v)
                        if len(s) > 1 and s != "<empty>":
                            extra = f" -> {s!r}"
                    print(f"  rsp+{i:02x} = {v:#x}{extra}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
    df.k32.TerminateProcess(pi.hProcess, 1)


if __name__ == "__main__":
    main()
