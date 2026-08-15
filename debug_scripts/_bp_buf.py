import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from tools.audit_calls import load_map, read_text_section

# 1) static: what's at More? site and add9 start
raw = Path("build_univ99/cmd_pure.exe").read_bytes()
trva, data, new_base = read_text_section(raw)
m = load_map(Path("build_univ99/rva.txt"))
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 add9 ===")
off = m[0xADD9]-trva
for insn in md.disasm(data[off:off+0x80], new_base+m[0xADD9]):
    print(f"  {insn.address:x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > new_base+m[0xADD9]+0x70: break
print("\n=== pe64 AE0D More? ===")
off = m[0xAE0D]-trva
for insn in md.disasm(data[off-0x10:off+0x40], new_base+m[0xAE0D]-0x10):
    mark=' <<<' if insn.address==new_base+m[0xAE0D] else ''
    print(f"  {insn.address:x}: {insn.mnemonic} {insn.op_str}{mark}")

# 2) x86 add9 / who calls / cmdline skip
src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from('<I',src,0x3c)[0]
n=struct.unpack_from('<H',src,e+6)[0]; opt=struct.unpack_from('<H',src,e+20)[0]; sec=e+24+opt
ib=struct.unpack_from('<I',src,e+24+28)[0]
for i in range(n):
    o=sec+i*40
    if src[o:o+5]==b'.text':
        va,rs,rp=struct.unpack_from('<III',src,o+12); text=src[rp:rp+rs]; tr=va; break
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 AE0D ===")
for insn in md32.disasm(text[0xAE0D-tr-0x10:0xAE0D-tr+0x30], ib+0xAE0D-0x10):
    mark=' <<<' if insn.address==ib+0xAE0D else ''
    print(f"  {insn.address:x}: {insn.mnemonic} {insn.op_str}{mark}")

# 3) runtime: dump FULL buffer at add9
k32=df.k32
exe=str(Path('build_univ99/cmd_pure.exe').resolve())
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=f'"{exe}" /c echo w2ktest'
ok=k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok
ev=df.DEBUG_EVENT(); ADD9=0x800146F4; orig=None; hProcess=None; t0=time.time()
while time.time()-t0<15:
    if not k32.WaitForDebugEvent(C.byref(ev),500): continue
    if ev.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess=ev.u.CreateProcessInfo.hProcess
        orig=df.read_process_mem(hProcess, ADD9, 1)[0]
        wr=C.c_size_t(0); k32.WriteProcessMemory(hProcess, C.c_void_p(ADD9), b'\xCC', 1, C.byref(wr))
    elif ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord; ec=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        if ec==0x80000003 and addr==ADD9:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(th)
            buf=df.read_process_mem(hProcess, ctx.Rcx, 600)
            # decode utf16
            try:
                s=buf.decode('utf-16-le', errors='replace')
                z=s.find('\x00')
                if z>=0: s=s[:z]
            except Exception as e:
                s=repr(buf)
            print('\n=== FULL BUF at add9 ===')
            print('len_chars', len(s))
            print(repr(s))
            print('has /c', '/c' in s.lower(), 'has echo', 'echo' in s.lower(), 'quote_count', s.count('"'))
            # also check stack homes for args
            print(f'RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} R8={ctx.R8:#x} R9={ctx.R9:#x}')
            k32.CloseHandle(th)
            k32.TerminateProcess(pi.hProcess,1)
            break
        elif ec==0xC0000005:
            print('AV before add9'); break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
