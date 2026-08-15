# Copy diamond tips from cmd_diam onto cmd_debs and smoke
import struct, pathlib, shutil, subprocess, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def load(p):
    pe=bytearray(pathlib.Path(p).read_bytes())
    e=struct.unpack_from("<I",pe,0x3C)[0]
    ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
    ib=struct.unpack_from("<Q",pe,e+24+24)[0]
    for i in range(ns):
        o=sec+i*40
        if pe[o:o+5]==b".text":
            vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
    return pe,e,ib,va,rp,rs

diam,_,ib,va,rp,_=load("build_univ229/cmd_diam.exe")
debs,_,_,_,_,_=load("build_univ230/cmd_debs.exe")
# copy diamond tip regions (64 bytes each)
for tip in [0x3624d, 0x1d4f4, 0x1d534, 0x1d574]:
    off=rp+(tip-va)
    debs[off:off+0x40]=diam[off:off+0x40]
    print("copied", hex(tip))
pathlib.Path("build_univ230/cmd_both.exe").write_bytes(debs)
# verify
md=Cs(CS_ARCH_X86,CS_MODE_64)
code=bytes(debs[rp:rp+0x40000])
for tip in [0x3624d, 0x1d574]:
    print(f"-- {tip:#x} --")
    for i, insn in enumerate(md.disasm(code[tip-va:tip-va+0x30], ib+tip)):
        if "r8" in insn.op_str or "r9" in insn.op_str or insn.mnemonic=="movabs":
            if insn.mnemonic=="movabs":
                print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if i>12: break

os.chdir("build_univ230")
r=subprocess.run(["cmd_both.exe","/c","echo","w2ktest"],capture_output=True,timeout=12)
print("exit",hex(r.returncode&0xffffffff))
print(r.stdout.decode("utf-8","replace")[:400])
print("w2ktest", b"w2ktest" in r.stdout)
