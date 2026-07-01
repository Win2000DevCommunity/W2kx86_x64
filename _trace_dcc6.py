#!/usr/bin/env python3
"""Find how execution reaches main+0x2DCC6."""
import os
import struct
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
WATCH = {
    0x8BE5: "after lea",
    0x8C40: "cmp edi",
    0x8C75: "jmp 8CB4",
    0x8CB4: "copycmd block",
    0x8CD6: "post-nop epilogue",
    0x8CF0: "iat f3e1",
    0x8D10: "d10",
    0x8D40: "d40",
    0x2DCC0: "fn6314 loop head",
    0x2DCC6: "fault site",
}


def patch_byte(proc, addr, val: int):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    buf = (C.c_ubyte * 1)(val)
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n))
    return ok and n.value == 1


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
    orig = {}
    de = df.DEBUG_EVENT()
    hits = []
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            for rva in WATCH:
                orig[rva] = df.read_process_mem(pi.hProcess, base + rva, 1)[0]
                patch_byte(pi.hProcess, base + rva, 0xCC)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            if ec == 0x80000003 and base and base <= ea < base + 0x500000:
                rva = ea - base
                if rva in orig:
                    ctx = df.get_thread_context(pi.hThread)
                    label = WATCH[rva]
                    print(f"{label} (main+0x{rva:x}): RIP={ctx.Rip:#x} RAX={ctx.Rax:#x} "
                          f"RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x}")
                    if rva in (0x2DCC0, 0x2DCC6):
                        raw = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x60)
                        print("  stack .text addrs:")
                        for i in range(0, len(raw) - 8, 8):
                            val = struct.unpack_from("<Q", raw, i)[0]
                            trva = val - base
                            if 0x1000 <= trva < 0x42000:
                                print(f"    [rsp+0x{i:x}] -> main+0x{trva:x}")
                    hits.append(label)
                    patch_byte(pi.hProcess, ea, orig[rva])
                    ctx.Rip = ea
                    df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and base:
                ctx = df.get_thread_context(pi.hThread)
                print(f"AV main+0x{ctx.Rip - base:x} after hits={hits}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} hits={hits}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
