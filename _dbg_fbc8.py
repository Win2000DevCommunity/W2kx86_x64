from __future__ import annotations
import ctypes as C, sys, time
from ctypes import wintypes
from pathlib import Path
import dbg_fault as df
from tools.audit_calls import load_map

DEBUG_PROCESS = 0x00000001

class STARTUPINFO(C.Structure):
    _fields_ = [('cb', wintypes.DWORD),('lpReserved', wintypes.LPWSTR),('lpDesktop', wintypes.LPWSTR),('lpTitle', wintypes.LPWSTR),('dwX', wintypes.DWORD),('dwY', wintypes.DWORD),('dwXSize', wintypes.DWORD),('dwYSize', wintypes.DWORD),('dwXCountChars', wintypes.DWORD),('dwYCountChars', wintypes.DWORD),('dwFillAttribute', wintypes.DWORD),('dwFlags', wintypes.DWORD),('wShowWindow', wintypes.WORD),('cbReserved2', wintypes.WORD),('lpReserved2', C.POINTER(C.c_byte)),('hStdInput', wintypes.HANDLE),('hStdOutput', wintypes.HANDLE),('hStdError', wintypes.HANDLE)]

class PROCESS_INFORMATION(C.Structure):
    _fields_ = [('hProcess', wintypes.HANDLE),('hThread', wintypes.HANDLE),('dwProcessId', wintypes.DWORD),('dwThreadId', wintypes.DWORD)]

class CONTEXT(C.Structure):
    _fields_ = [('P1Home', C.c_ulonglong),('P2Home', C.c_ulonglong),('P3Home', C.c_ulonglong),('P4Home', C.c_ulonglong),('P5Home', C.c_ulonglong),('P6Home', C.c_ulonglong),('ContextFlags', wintypes.DWORD),('MxCsr', wintypes.DWORD),('SegCs', wintypes.WORD),('SegDs', wintypes.WORD),('SegEs', wintypes.WORD),('SegFs', wintypes.WORD),('SegGs', wintypes.WORD),('SegSs', wintypes.WORD),('EFlags', wintypes.DWORD),('Dr0', C.c_ulonglong),('Dr1', C.c_ulonglong),('Dr2', C.c_ulonglong),('Dr3', C.c_ulonglong),('Dr6', C.c_ulonglong),('Dr7', C.c_ulonglong),('Rax', C.c_ulonglong),('Rcx', C.c_ulonglong),('Rdx', C.c_ulonglong),('Rbx', C.c_ulonglong),('Rsp', C.c_ulonglong),('Rbp', C.c_ulonglong),('Rsi', C.c_ulonglong),('Rdi', C.c_ulonglong),('R8', C.c_ulonglong),('R9', C.c_ulonglong),('R10', C.c_ulonglong),('R11', C.c_ulonglong),('R12', C.c_ulonglong),('R13', C.c_ulonglong),('R14', C.c_ulonglong),('R15', C.c_ulonglong),('Rip', C.c_ulonglong),('FltSave', C.c_byte * 512)]

def u32(proc, addr):
    b = df.read_process_mem(proc, addr, 4)
    return int.from_bytes(b, 'little') if len(b)==4 else 0

def u64(proc, addr):
    b = df.read_process_mem(proc, addr, 8)
    return int.from_bytes(b, 'little') if len(b)==8 else 0

def main():
    df.suppress_fault_ui()
    exe = Path(sys.argv[1] if len(sys.argv)>1 else 'build_univ103/cmd_pure.exe').resolve()
    m = load_map(exe.parent / 'rva.txt')
    k32 = df.k32
    si = STARTUPINFO(); si.cb=C.sizeof(si); si.dwFlags=1; si.wShowWindow=0
    pi = PROCESS_INFORMATION()
    cmd = '"%s" /c echo w2ktest' % exe
    if not k32.CreateProcessW(None, C.create_unicode_buffer(cmd), None, None, False, DEBUG_PROCESS, None, str(exe.parent), C.byref(si), C.byref(pi)):
        print('CreateProcess failed', k32.GetLastError()); return 1
    base=None; bps={}; hits=0
    de = df.DEBUG_EVENT(); t0=time.time()
    while time.time()-t0 < 15 and hits < 6:
        if not k32.WaitForDebugEvent(C.byref(de), 500):
            continue
        code = de.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print('base=%x' % base)
            for name,rva in (('add9', m[0xADD9]),('ae2a', 0x147A5),('test', 0x147B5),('b186', m[0xB186])):
                addr = base + rva
                old = df.read_process_mem(pi.hProcess, addr, 1)
                if old:
                    bps[addr]=(name, old[0]); df.patch_byte(pi.hProcess, addr, 0xCC); print('bp %s @%x' % (name, addr))
            h=de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xffffffff
            addr = er.ExceptionAddress or 0
            if ecode == 0x80000003 and addr in bps:
                name, orig = bps[addr]
                ht = k32.OpenThread(0x1F03FF, False, de.dwThreadId)
                ctx = CONTEXT(); ctx.ContextFlags=0x10001F
                k32.GetThreadContext(ht, C.byref(ctx))
                fbc8=u32(pi.hProcess, base+0x6DBC8); c8d8=u32(pi.hProcess, base+0x6A8D8)
                print('HIT %s rip=%x rcx=%x rdx=%x rsi=%x' % (name, ctx.Rip, ctx.Rcx, ctx.Rdx, ctx.Rsi))
                print('  [fbc8]=%x [c8d8]=%x' % (fbc8, c8d8))
                if fbc8: print('  *fbc8', df.read_process_mem(pi.hProcess, fbc8, 16))
                if c8d8: print('  *c8d8', df.read_process_mem(pi.hProcess, c8d8, 48))
                if ctx.Rbp: print('  [rbp+10]=%x [rbp+18]=%x' % (u64(pi.hProcess, ctx.Rbp+0x10), u64(pi.hProcess, ctx.Rbp+0x18)))
                hits += 1
                df.patch_byte(pi.hProcess, addr, orig)
                ctx.EFlags |= 0x100; ctx.Rip = addr
                k32.SetThreadContext(ht, C.byref(ctx))
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
                k32.WaitForDebugEvent(C.byref(de), 2000)
                if addr in bps: df.patch_byte(pi.hProcess, addr, 0xCC)
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
                k32.CloseHandle(ht)
                continue
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    print('done hits', hits)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
