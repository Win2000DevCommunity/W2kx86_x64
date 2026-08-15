import pathlib, struct, shutil, subprocess, os, sys, ctypes as C
sys.path.insert(0,".")
import dbg_fault as df

src=pathlib.Path("build_univ230/cmd_fix5.exe")
dst=pathlib.Path("build_univ230/cmd_fix13.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

def ro(rva): return rp+(rva-va)

# d9bc 3-pop only
pe[ro(0xd9bc):ro(0xd9bc)+10]=bytes.fromhex("b8010000005f5e5bc9c3")
# surgical add rsp nop at d41c, d6bf, d6f2 (and check for more in d08c only)
n=0
for rva in range(0xd08c, 0xdeb1):
    off=ro(rva)
    if pe[off:off+9]==bytes.fromhex("4c89ec415d4883c408"):
        pe[off+5:off+9]=b"\x90"*4; n+=1; print(f"  nop add @ {rva:#x}")
print("d08c addrsp", n)
# cep
epi=bytes.fromhex("4889e85f5e5d5bc3"); home=bytes.fromhex("48894c2408")
n_cep=0; i=rp; end=rp+rs
while i < end-5:
    if pe[i]==0xE8:
        rel=struct.unpack_from("<i",pe,i+1)[0]; tgt=i+5+rel
        if rp<=tgt<=end-13 and pe[tgt:tgt+8]==epi and pe[tgt+8:tgt+13]==home:
            struct.pack_into("<i",pe,i+1,(tgt+8)-(i+5)); n_cep+=1
        i+=5
    else: i+=1
print("cep", n_cep)
dst.write_bytes(pe)

os.chdir("build_univ230")
# smoke
r=subprocess.run(["cmd_fix13.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1000])
print("has w2ktest", "w2ktest" in out)

# if fail, quick bp
if "w2ktest" not in out:
    k32=C.WinDLL("kernel32", use_last_error=True)
    df.suppress_fault_ui()
    exe=os.path.abspath("cmd_fix13.exe"); IB=0x80000000
    BPS={IB+0xc59c:"after_d08c", IB+0xc5e5:"call_28a0c", IB+0xc5ea:"after_28a0c", IB+0xc622:"call_big", IB+0xc627:"after_big"}
    si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
    cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
    assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
    orig={}; de=df.DEBUG_EVENT(); skips=0
    while k32.WaitForDebugEvent(C.byref(de),20000):
        cont=df.DBG_CONTINUE
        if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
            for va in BPS:
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
                    print("HIT",BPS[bp],"rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx),"rsi",hex(ctx.Rsi),"rbx",hex(ctx.Rbx))
                    if BPS[bp]=="after_d08c" and ctx.Rsi>0x10000:
                        b=df.read_process_mem(pi.hProcess,ctx.Rsi,40)
                        if b:
                            try: print(" ",b.decode("utf-16-le","replace")[:30])
                            except: pass
                else:
                    skips+=1
                    if skips>5:
                        ctx=df.get_thread_context(pi.hThread); print("int3",hex(ctx.Rip)); k32.TerminateProcess(pi.hProcess,1); break
            elif code==0xC0000005:
                ctx=df.get_thread_context(pi.hThread)
                print("AV",hex(ctx.Rip),hex(ctx.Rcx),hex(ctx.Rax))
                if not de.u.Exception.dwFirstChance: k32.TerminateProcess(pi.hProcess,1); break
                cont=df.DBG_EXCEPTION_NOT_HANDLED
            elif code==0xC0000374:
                print("HEAP",hex(df.get_thread_context(pi.hThread).Rip)); k32.TerminateProcess(pi.hProcess,1); break
            elif code!=0x80000004: cont=df.DBG_EXCEPTION_NOT_HANDLED
        elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
        k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
