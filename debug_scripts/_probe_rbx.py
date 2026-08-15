#!/usr/bin/env python3
"""Read RBX wide string at echo-tail probes."""
import ctypes as C
import struct
import sys
import dbg_fault as df

def read_wstr(h, addr, n=64):
    raw = df.read_process_mem(h, addr, n * 2)
    chars = []
    for i in range(0, len(raw) - 1, 2):
        w = struct.unpack_from('<H', raw, i)[0]
        if w == 0:
            break
        chars.append(chr(w) if w < 0x10000 else '?')
    return ''.join(chars)

def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else r'..\win2000_x64\cmd_shim.exe'
    args = sys.argv[2:] or ['/c', 'echo', 'test']
    df.suppress_fault_ui()
    cmd = '"' + exe + '" ' + ' '.join(args)
    si = df.STARTUPINFO(); si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(None, cmd, None, None, False, 0, None, None,
                          C.byref(si), C.byref(pi))
    base = 0x80000000
    probes = {0x932F: 'echo-tail', 0x935E: 'wcslen-rcx', 0x938F: 'pre-cp'}
    ctx = df.CONTEXT()
    ctx.ContextFlags = df.CONTEXT_FULL
    while True:
        df.k32.WaitForSingleObject(pi.hThread, 200)
        if df.k32.GetExitCodeProcess(pi.hProcess, C.byref(ec := C.c_ulong())) and ec.value != 259:
            print(f'exit=0x{ec.value:X}')
            break
        df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
        rva = ctx.Rip - base
        if rva in probes:
            print(f'\n--- {probes[rva]} main+0x{rva:X} ---')
            print(f'  RBX=0x{ctx.Rbx:X} RCX=0x{ctx.Rcx:X} RDX=0x{ctx.Rdx:X} RDI=0x{ctx.Rdi:X}')
            if ctx.Rbx > 0x10000:
                try:
                    print(f'  RBX str: {read_wstr(pi.hProcess, ctx.Rbx)!r}')
                except Exception as e:
                    print(f'  RBX read err: {e}')
            if ctx.Rcx > 0x10000:
                try:
                    print(f'  RCX str: {read_wstr(pi.hProcess, ctx.Rcx)!r}')
                except Exception:
                    pass
            # skip probe byte
            buf = df.read_process_mem(pi.hProcess, ctx.Rip, 1)
            if buf[0] == 0xCC:
                ctx.Rip += 1
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
        df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
        df.k32.ResumeThread(pi.hThread)
    df.k32.TerminateProcess(pi.hProcess, 0)
    df.k32.CloseHandle(pi.hProcess)
    df.k32.CloseHandle(pi.hThread)

if __name__ == '__main__':
    main()
