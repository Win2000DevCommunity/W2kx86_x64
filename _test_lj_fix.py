import pathlib, struct, shutil, subprocess, sys, time
import pefile
import w2kseh64

# Rebuild longjmp bytes and patch into existing shim
fresh = w2kseh64.build_longjmp(with_nv_save=True)
shim_path = pathlib.Path("build_univ258/w2kshim64.dll")
# also copy for lj probe
data = bytearray(shim_path.read_bytes())
pe = pefile.PE(data=bytes(data))
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name == b"longjmp":
        rva = exp.address
        break
# find file offset
for s in pe.sections:
    if s.VirtualAddress <= rva < s.VirtualAddress + s.SizeOfRawData:
        off = s.PointerToRawData + (rva - s.VirtualAddress)
        break
old = bytes(data[off:off+len(fresh)])
print("old starts", old[:20].hex())
print("new starts", fresh[:20].hex())
# keep existing lea disp from old
# find lea rax,[rip+disp] in both and copy disp from old to new
new = bytearray(fresh)
for i in range(len(new)-7):
    if new[i:i+3] == b"\x48\x8d\x05" and old[i:i+3] == b"\x48\x8d\x05":
        new[i+3:i+7] = old[i+3:i+7]
        print("preserved lea disp", struct.unpack_from("<i", old, i+3)[0])
        break
data[off:off+len(new)] = new
# also patch setjmp if length same
fresh_sj = w2kseh64.build_setjmp3(with_nv_save=True)
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name == b"_setjmp3":
        rva_sj = exp.address
        break
for s in pe.sections:
    if s.VirtualAddress <= rva_sj < s.VirtualAddress + s.SizeOfRawData:
        off_sj = s.PointerToRawData + (rva_sj - s.VirtualAddress)
        break
old_sj = bytes(data[off_sj:off_sj+len(fresh_sj)])
new_sj = bytearray(fresh_sj)
for i in range(len(new_sj)-7):
    if new_sj[i:i+3] == b"\x48\x8d\x05" and old_sj[i:i+3] == b"\x48\x8d\x05":
        new_sj[i+3:i+7] = old_sj[i+3:i+7]
        break
if len(new_sj) <= len(old_sj)+8:
    data[off_sj:off_sj+len(new_sj)] = new_sj
    print("patched setjmp", len(new_sj))

out = pathlib.Path("build_univ258/w2kshim64_lj.dll")
out.write_bytes(data)
# Use with probe: need shim named w2kshim64.dll next to exe
# Patch probe_lj to use sign-ext -1 and copy shim
exe = pathlib.Path("build_univ258/cmd_probe_lj.exe")
# copy exe+shim to test dir
td = pathlib.Path("build_univ258/ljtest")
td.mkdir(exist_ok=True)
shutil.copy2(exe, td/"cmd.exe")
shutil.copy2(out, td/"w2kshim64.dll")
# also patch -1 in the copied exe
peb = bytearray((td/"cmd.exe").read_bytes())
sig=bytes.fromhex("48baffffffff00000000")
repl=bytes.fromhex("48c7c2ffffffff909090")
# only at waiter 4583c area - file offset
e=struct.unpack_from("<I", peb, 0x3C)[0]
ns=struct.unpack_from("<H", peb, e+6)[0]; so=struct.unpack_from("<H", peb, e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if peb[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", peb, o+8); break
# RVA 4583C -> file
fo = rp + (0x4583C - va)
print("at 4583C", peb[fo:fo+10].hex())
if peb[fo:fo+10]==sig:
    peb[fo:fo+10]=repl
    print("patched waiter -1")
(td/"cmd.exe").write_bytes(peb)

# smoke
r=subprocess.run([sys.executable,"dbg_fault.py",str(td/"cmd.exe"),"/c","echo","w2ktest"],
                 capture_output=True,text=True,timeout=30,cwd=str(td))
print("/c", r.returncode, [ln for ln in (r.stdout or "").splitlines() if "w2ktest" in ln or "exit" in ln][-3:])
p=subprocess.Popen([sys.executable, str(pathlib.Path("dbg_fault.py").resolve()), str((td/"cmd.exe").resolve())],
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=str(td))
time.sleep(3)
print("alive", p.poll() is None)
outb=p.communicate(timeout=5)[0] if p.poll() is not None else (p.terminate() or p.communicate(timeout=3)[0])
text=outb.decode("utf-8","replace")
for ln in text.splitlines():
    if "EXCEPTION" in ln or "code=0x" in ln or "off=" in ln or "STACK" in ln or "RSP=" in ln:
        print(ln)
