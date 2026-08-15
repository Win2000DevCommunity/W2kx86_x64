import struct, pathlib, sys, ctypes as C, os
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df

exe = os.path.abspath(r"build_univ228\cmd_combo.exe")
pe = bytearray(open(exe,"rb").read())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
out = bytearray(pe[rp:rp+rs])
bps = {}
watch = [0x1d5b4, 0x1e2b4, 0x1d5e7, 0x1d7f4, 0x1d61f]
for rva in watch:
    bps[rva]=out[rva-va]; out[rva-va]=0xCC
pe[rp:rp+rs]=out
bp_exe=os.path.abspath(r"build_univ228\cmd_combo_bp3.exe"); open(bp_exe,"wb").write(pe)

k32=df.k32
k32.OpenThread.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
k32.OpenThread.restype=wintypes.HANDLE
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmdline=C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
assert k32.CreateProcessW(None,cmdline,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.path.dirname(bp_exe),C.byref(si),C.byref(pi))

def read_wstr(proc, addr, n=64):
    raw=df.read_process_mem(proc, addr, n*2)
    if not raw: return ""
    try: return raw.decode("utf-16le", errors="replace").split("\0")[0][:60]
    except: return raw.hex()

hits=[]
while len(hits)<20:
    ev=df.DEBUG_EVENT()
    if not k32.WaitForDebugEvent(C.byref(ev),20000):
        print("timeout"); break
    cont=df.DBG_CONTINUE
    if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord
        if er.ExceptionCode==0x80000003:
            ht=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(ht)
            rip=ctx.Rip-1; rva=(rip-ib)&0xffffffff
            if rva in bps:
                buf=(C.c_ubyte*1)(bps[rva]); wr=C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess,C.c_void_p(rip),buf,1,C.byref(wr))
                ctx.Rip=rip
                # globals
                c8d8=df.read_u64(pi.hProcess, ib+0x588d8) & 0xffffffff  # dword slot?
                # actually c8d8 is pointer stored as dword historically - read qword
                c8 = struct.unpack_from("<Q", df.read_process_mem(pi.hProcess, ib+0x588d8, 8) or b"\0"*8)[0]
                fbc8=struct.unpack_from("<Q", df.read_process_mem(pi.hProcess, ib+0x5bbc8, 8) or b"\0"*8)[0]
                fae0=struct.unpack_from("<I", df.read_process_mem(pi.hProcess, ib+0x5bae0, 4) or b"\0"*4)[0]
                fbe2=df.read_process_mem(pi.hProcess, ib+0x5bbe2, 16)
                bufs=""
                if 0x10000 < c8 < 0x90000000:
                    bufs=read_wstr(pi.hProcess, c8)
                elif True:
                    bufs=read_wstr(pi.hProcess, ib+0x60320)
                print(f"hit {rva:#x} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x}")
                print(f"  c8d8={c8:#x} fae0={fae0:#x} fbc8={fbc8:#x}")
                print(f"  cmdline={bufs!r}")
                print(f"  fbe2={fbe2.hex() if fbe2 else None}")
                hits.append(rva)
                # one-shot
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            ht=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(ht)
            print("AV", hex(ctx.Rip), "acc", hex(er.ExceptionInformation[1] if er.NumberParameters>1 else 0))
            k32.CloseHandle(ht); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
