#!/usr/bin/env python3
"""Hit-test CRT/cmd RVAs under a debugger."""
import os
import struct
import ctypes as C

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = {
    0x877B: "CRT entry",
    0x887D: "after __getmainargs1",
    0x8901: "after __getmainargs2",
    0x8A4E: "fn6314 cmdline",
    0x8EB9: "cmd main",
    0x8F06: "main wcslen",
    0x92A4: "exec switch call",
}


def rva_to_off(data, rva):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt_sz = struct.unpack_from("<H", data, pe + 20)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    sec = pe + 24 + opt_sz
    for i in range(n):
        o = sec + i * 40
        vs, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        if va <= rva < va + max(vs, rawsz):
            return rawptr + (rva - va)
    return None


def main():
    df.suppress_fault_ui()
    pe_data = open(EXE, "rb").read()
    patches = {}
    for rva, label in BPS.items():
        off = rva_to_off(pe_data, rva)
        if off is None:
            print(f"skip unmapped {rva:#x}")
            continue
        patches[rva] = (label, pe_data[off])

    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    ok = df.k32.CreateProcessW(
        EXE, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    hits = []
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = df.DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            for rva, (_, orig) in patches.items():
                df.k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(base + rva),
                    C.c_char(0xCC), 1, C.byref(C.c_size_t(0)))
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            ec = de.u.ExitProcess.dwExitCode & 0xFFFFFFFF
            print(f"exit=0x{ec:08x}")
            print("hits:", hits)
            break
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            rva = (er.ExceptionAddress or 0) - (base or 0)
            if ecode == 0x80000003 and rva in patches and rva not in {h[0] for h in hits}:
                label = patches[rva][0]
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"  hit {label} main+0x{rva:x} RAX={ctx.Rax:#x} RSI={ctx.Rsi:#x}")
                hits.append((rva, label))
                orig = patches[rva][1]
                df.k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(base + rva),
                    C.c_char(orig), 1, C.byref(C.c_size_t(0)))
                ctx.Rip = base + rva
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ecode == 0xC0000005:
                print(f"AV main+0x{rva:x}")
                break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
