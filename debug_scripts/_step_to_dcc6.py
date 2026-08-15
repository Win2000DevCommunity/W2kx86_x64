#!/usr/bin/env python3
"""Step from main+0x8BE5 until fn6314 loop or fault."""
import os
import struct
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))


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
    stepping = False
    steps = 0
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            ctx = df.get_thread_context(pi.hThread)
            rva = ea - (base or 0)
            if ec == 0x80000003 and base and rva == 0x8BE5:
                stepping = True
                steps = 0
                df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
                continue
            if stepping and ec == 0x80000004:  # single-step / breakpoint after continue
                steps += 1
                rva = ctx.Rip - base
                if steps <= 5 or rva in (0x8C75, 0x8CB4, 0x8CD6, 0x2DCC0, 0x2DCC6) or steps % 200 == 0:
                    print(f"step {steps}: main+0x{rva:x} RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} RSI={ctx.Rsi:#x}")
                if 0x2DC0B <= rva <= 0x2DD68:
                    print(f"ENTER fn6314 body at step {steps} main+0x{rva:x}")
                    raw = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x80)
                    for i in range(0, len(raw) - 8, 8):
                        val = struct.unpack_from("<Q", raw, i)[0]
                        trva = val - base
                        if 0x1000 <= trva < 0x42000:
                            print(f"  [rsp+0x{i:x}] -> main+0x{trva:x}")
                    break
                if steps > 5000:
                    print("give up at", hex(rva))
                    break
                ctx.EFlags |= 0x100
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and base:
                print(f"AV main+0x{ctx.Rip-base:x} after {steps} steps from 8BE5")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        cont = df.DBG_CONTINUE
        if stepping and de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            if (er.ExceptionCode & 0xFFFFFFFF) not in (0x80000003, 0x80000004, 0xC0000005):
                cont = df.DBG_EXCEPTION_NOT_HANDLED
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)


if __name__ == "__main__":
    main()
