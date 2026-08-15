import sys, ctypes as C, struct
from pathlib import Path
sys.path.insert(0,'.')
import dbg_fault as df

# Patch int3 at PutMsg entry 0x26150 and at call rbx 0x2656f
pe=bytearray(Path('build_univ176/cmd_pure_h.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if pe[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8); tr=va; break
out=bytearray(pe[rp:rp+rs])
sites={0x26150: out[0x26150-tr], 0x2617a: out[0x2617a-tr], 0x2656f: out[0x2656f-tr], 0x264d1: out[0x264d1-tr]}
for s in sites: out[s-tr]=0xCC
pe[rp:rp+rs]=out
Path('build_univ176/cmd_bp.exe').write_bytes(pe)

exe=str(Path('build_univ176/cmd_bp.exe').resolve())
k32=df.k32
si=df.STARTUPINFO(); si.cb=C.sizeof(si)
pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer('\"%s\" /c echo w2ktest'%exe)
assert k32.CreateProcessW(None,cmd,None,None,False,df.DEBUG_PROCESS,None,str(Path(exe).parent),C.byref(si),C.byref(pi))
IB=0x80000000
ev=df.DEBUG_EVENT()
hits=[]
while len(hits)<8:
    if not k32.WaitForDebugEvent(C.byref(ev), 10000):
        print('timeout'); break
    if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord
        code=er.ExceptionCode
        addr=er.ExceptionAddress or 0
        if code==0x80000003:
            ctx=df.CONTEXT(); ctx.ContextFlags=df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rva=ctx.Rip-IB
            hits.append(rva)
            print('BP rva=%#x rbx=%#x rax=%#x rsp=%#x'%(rva, ctx.Rbx, ctx.Rax, ctx.Rsp))
            # restore byte and step
            if rva in sites:
                # write original back and set RF or single step - just put original and move rip... 
                # simpler: write orig, continue
                buf=C.c_ubyte(sites[rva]); n=C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(ctx.Rip), C.byref(buf), 1, C.byref(n))
            k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
            continue
        if code in (0xC0000005,0xC00000FD):
            ctx=df.CONTEXT(); ctx.ContextFlags=df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print('FAULT %#x rip=%#x rbx=%#x'%(code, ctx.Rip, ctx.Rbx))
            break
        k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_EXCEPTION_NOT_HANDLED); continue
    if ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print('exit'); break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
k32.TerminateProcess(pi.hProcess,1)