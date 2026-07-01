#!/usr/bin/env python3
import os, struct, ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = {0x8D83: "after loop", 0x8DE0: "de0", 0x8DFD: "dfd", 0x8E20: "e20", 0x8777: "entry"}


def patch_byte(proc, addr, val):
    old = C.c_uint32(0)
    df.k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    buf = (C.c_ubyte * 1)(val)
    n = C.c_size_t(0)
    df.k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n))


def main():
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO(); si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(EXE, C.create_unicode_buffer(cmdline), None, None, False,
                          df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    base = None; orig = {}; de = df.DEBUG_EVENT(); hits = []
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            for rva in BPS:
                orig[rva] = df.read_process_mem(pi.hProcess, base + rva, 1)[0]
                patch_byte(pi.hProcess, base + rva, 0xCC)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            if ec == 0x80000003 and base and (ea - base) in orig:
                ctx = df.get_thread_context(pi.hThread)
                rva = ea - base
                print(f"{BPS[rva]}: RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} R12={ctx.R12:#x}")
                hits.append(BPS[rva])
                patch_byte(pi.hProcess, ea, orig[rva])
                ctx.Rip = ea; df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and base:
                ctx = df.get_thread_context(pi.hThread)
                print(f"AV RIP={ctx.Rip:#x} main+0x{ctx.Rip-base:x} hits={hits}")
                raw = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x80)
                for i in range(0, len(raw)-8, 8):
                    val = struct.unpack_from("<Q", raw, i)[0]
                    trva = val - base
                    if 0x1000 <= trva < 0x42000:
                        print(f"  [rsp+0x{i:x}] -> main+0x{trva:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)

if __name__ == "__main__":
    main()
