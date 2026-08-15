import struct, pathlib, subprocess, sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ228/full.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)

print("==== 34161 caller ====")
for insn in md.disasm(blob[0x34120-va:0x34180-va], ib+0x34120):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

print("==== 48919 current ====")
for insn in md.disasm(blob[0x48900-va:0x48930-va], ib+0x48900):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

# Patch 48919 to: mov rax, rbx; mov rsp, rbp; pop rbp; ret
# 48 89 d8  48 89 ec  5d  c3  then nops
stub = bytes.fromhex("4889d84889ec5dc3")
at = 0x48919 - va
print("old", blob[at:at+16].hex())
# keep space - original was 6 pops + ret = 7 bytes? 
# pop rdi/rsi/rbp/rbx/rcx/rcx/ret = 6*1+1 = 7 bytes only!
print("epi bytes", blob[at:at+16].hex())
# Actually:
# 48919: 5f 5e 5d 5b 59 59 c3 = 7 bytes
# Our stub is 8 bytes - need 1 more byte of room or use shorter form
# mov eax, ebx (89 d8) ; leave (c9) ; ret (c3) = 4 bytes, rax high cleared? 
# Better: 48 89 d8 (mov rax,rbx) ; c9 (leave) ; c3 (ret) = 5 bytes - fits in 7
stub = bytes.fromhex("4889d8c9c3")
pad = 7 - len(stub)
blob[at:at+7] = stub + b"\x90"*pad
print("new", blob[at:at+16].hex())
for insn in md.disasm(blob[0x48900-va:0x48930-va], ib+0x48900):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

pe[rp:rp+rs] = blob
outp = pathlib.Path("build_univ228/cmd_leave.exe")
outp.write_bytes(pe)
df.suppress_fault_ui()
r = subprocess.run([str(outp.resolve()), "/c", "echo", "w2ktest"], capture_output=True,
                   timeout=25, cwd=str(outp.parent),
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
print("exit", hex(r.returncode & 0xffffffff))
print("stdout", r.stdout[:300])
print("w2ktest", b"w2ktest" in r.stdout)
