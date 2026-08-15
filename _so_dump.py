import sys, ctypes as C, struct, collections
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0,'.')
import dbg_fault as df

# What's at data RVAs?
pe=Path('build_univ176/cmd_pure_f.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
secs={}
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0].decode(errors='replace')
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    secs[name]=(va,rp,rs,vs)
    print(name, 'va=%#x raw=%#x rs=%#x vs=%#x'%(va,rp,rs,vs))

for rva in [0x60528,0x6253A,0x62596,0x60320]:
    for name,(va,rp,rs,vs) in secs.items():
        if va <= rva < va+max(rs,vs):
            off=rp+(rva-va)
            chunk=pe[off:off+32]
            print('rva %#x in %s fileoff %#x: %s'%(rva,name,off,chunk.hex()))
            # as utf16
            try:
                print('  as u16:', pe[off:off+64].decode('utf-16le',errors='replace')[:40])
            except: pass
            break

# Find what code looks like around recursion - sample RIP via debug with SuspendThread polling
exe = str(Path('build_univ176/cmd_pure_f.exe').resolve())
k32 = df.k32
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer('\"%s\" /c echo w2ktest' % exe)
cwd = str(Path(exe).parent)
assert k32.CreateProcessW(None, cmd, None, None, False, df.DEBUG_PROCESS, None, cwd, C.byref(si), C.byref(pi))
IB=0x80000000
ev=df.DEBUG_EVENT()
hits=collections.Counter()
samples=0
while samples < 200000:
    if not k32.WaitForDebugEvent(C.byref(ev), 10):
        # poll RIP
        ctx=df.CONTEXT(); ctx.ContextFlags=df.CONTEXT_CONTROL
        if k32.GetThreadContext(pi.hThread, C.byref(ctx)):
            if IB <= ctx.Rip < IB+0x80000:
                hits[(ctx.Rip-IB)&~0xf] += 1
                samples += 1
        continue
    code=ev.dwDebugEventCode
    if code==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord
        ec=er.ExceptionCode
        if ec==0x80000003:
            k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE); continue
        if ec in (0xC0000005,0xC00000FD):
            ctx=df.CONTEXT(); ctx.ContextFlags=df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print('FAULT %#x rip=%#x rva=%#x rsp=%#x'%(ec,ctx.Rip, ctx.Rip-IB if IB<=ctx.Rip<IB+0x200000 else -1, ctx.Rsp))
            buf=(C.c_ulonglong*48)(); nread=C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 48*8, C.byref(nread))
            seen=collections.Counter()
            for i,v in enumerate(buf):
                if IB<=v<IB+0x100000:
                    seen[v-IB]+=1
                    if i<24: print('  rsp+%#x -> %#x'%(i*8,v-IB))
            print('top stack rva counts', seen.most_common(8))
            break
        k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_EXCEPTION_NOT_HANDLED); continue
    if code==df.EXIT_PROCESS_DEBUG_EVENT:
        print('exit'); break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
print('hot rvas', hits.most_common(15))
k32.TerminateProcess(pi.hProcess,1)