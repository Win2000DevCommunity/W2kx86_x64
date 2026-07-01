"""Print resolved IAT and first real exception for cmd_shim."""
import ctypes as C
import os
import struct
import sys

import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()


def read_mem(proc, addr, size):
    buf = (C.c_char * size)()
    n = C.c_size_t(0)
    if k32.ReadProcessMemory(proc, C.c_void_p(addr), buf, size, C.byref(n)):
        return bytes(buf[:n.value])
    return b""


def main():
    exe = sys.argv[1]
    args = sys.argv[2:]
    cmdline = '"' + exe + '" ' + " ".join(args)
    si = df.STARTUPINFO()
    si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None,
        C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    de = df.DEBUG_EVENT()
    n_exc = 0
    while True:
        if not k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
            break
        code = de.dwDebugEventCode
        status = df.DBG_CONTINUE
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"main base=0x{base:x}")
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            if ecode == 0x80000003 and n_exc == 0:
                n_exc += 1
            else:
                addr = er.ExceptionAddress or 0
                print(f"exception code=0x{ecode:08x} addr=0x{addr:x}")
                if base:
                    for name, rva in [("_except_handler3", 0x6ced8),
                                      ("try_call_slot", 0x6d5a1),
                                      ("__set_app_type", 0x6d5c1),
                                      ("__getmainargs", 0x6d5a9)]:
                        slot = read_mem(pi.hProcess, base + rva, 8)
                        if len(slot) == 8:
                            val = struct.unpack("<Q", slot)[0]
                            print(f"  IAT {name} rva=0x{rva:x} -> 0x{val:x}")
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"  RIP=0x{ctx.Rip:x} RBX=0x{ctx.Rbx:x} RSP=0x{ctx.Rsp:x}")
                for off in range(0, 0x60, 8):
                    slot = read_mem(pi.hProcess, ctx.Rsp + off, 8)
                    if len(slot) == 8:
                        val = struct.unpack("<Q", slot)[0]
                        tag = ""
                        if base and base <= val < base + 0x200000:
                            tag = f" main+0x{val - base:x}"
                        elif 0x1800100000 <= val < 0x1800200000:
                            tag = f" shim+0x{val - 0x1800100000:x}"
                        print(f"    [rsp+0x{off:x}]=0x{val:016x}{tag}")
                if base:
                    scope = base + 0x3f8c4
                    mem = read_mem(pi.hProcess, ctx.Rsp - 0x200, 0xA00)
                    for i in range(0, len(mem) - 32, 8):
                        nxt = struct.unpack("<Q", mem[i:i + 8])[0]
                        hnd = struct.unpack("<Q", mem[i + 8:i + 16])[0]
                        scp = struct.unpack("<Q", mem[i + 16:i + 24])[0]
                        tl = struct.unpack("<I", mem[i + 24:i + 28])[0]
                        if scp == scope or hnd in (base + 0x3f820, 0x1800100000 + 0x1210,
                                                   0x1800100000 + 0x10c0):
                            addr = ctx.Rsp - 0x200 + i
                            print(f"    SEH frame @0x{addr:x}: next=0x{nxt:x} "
                                  f"handler=0x{hnd:x} scope=0x{scp:x} try={tl}")
                n_exc += 1
                if n_exc >= 5:
                    break
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
