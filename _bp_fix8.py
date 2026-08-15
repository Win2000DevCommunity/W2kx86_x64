import pathlib, struct, shutil, subprocess, os, sys, ctypes as C
sys.path.insert(0,".")
import dbg_fault as df

src=pathlib.Path("build_univ230/cmd_fix5.exe")
dst=pathlib.Path("build_univ230/cmd_fix8.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
off=rp+(0xd9bc-va)
pe[off:off+10]=bytes.fromhex("b8010000005f5e5bc9c3")
dst.write_bytes(pe)

# smoke + bp
os.chdir("build_univ230")
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
exe=os.path.abspath("cmd_fix8.exe")
IB=0x80000000
NAMES={
 IB+0xc59c:"after_d08c",
 IB+0xc5c0:"alloc2",
 IB+0xc5c5:"after_alloc2",
 IB+0xc5e5:"call_28a04",
 IB+0xc5ea:"after_28a04",
 IB+0xc622:"call_big",
}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va in NAMES:
            b=df.read_process_mem(pi.hProcess,va,1)
            if b: orig[va]=b[0]; df.patch_byte(pi.hProcess,va,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003:
            bp=addr if addr in orig else (addr-1 if addr-1 in orig else None)
            if bp is not None:
                ctx=df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess,bp,orig[bp]); ctx.Rip=bp; ctx.EFlags&=~0x100
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
                print("HIT",NAMES[bp],"rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx),"rsi",hex(ctx.Rsi),"rdi",hex(ctx.Rdi),"rbx",hex(ctx.Rbx))
                if ctx.Rsi>0x10000 and ctx.Rsi<0x7fffffffffff:
                    b=df.read_process_mem(pi.hProcess,ctx.Rsi,48)
                    if b:
                        try: print("  [rsi]",b.decode("utf-16-le","replace")[:40])
                        except: pass
            else:
                skips+=1
                if skips>4:
                    ctx=df.get_thread_context(pi.hThread)
                    print("int3",hex(ctx.Rip))
                    k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000005:
            ctx=df.get_thread_context(pi.hThread)
            print("AV",hex(ctx.Rip),"rcx",hex(ctx.Rcx),"rsi",hex(ctx.Rsi),"rax",hex(ctx.Rax))
            if not de.u.Exception.dwFirstChance:
                k32.TerminateProcess(pi.hProcess,1); break
            cont=df.DBG_EXCEPTION_NOT_HANDLED
        elif code==0xC0000374:
            ctx=df.get_thread_context(pi.hThread)
            print("HEAP",hex(ctx.Rip))
            k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004: cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
