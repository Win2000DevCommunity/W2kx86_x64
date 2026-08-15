from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ230/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]; so=struct.unpack_from("<H", pe, e+20)[0]; sec=e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
# find pattern: mov rcx,rsi; mov rdx,rbx; mov r8,rdi near push r13 after test esi
pat=bytes.fromhex("4889f14889da4989f84155")
idx=0; hits=[]
while True:
    j=code.find(pat, idx)
    if j<0: break
    hits.append(j); idx=j+1
print("pattern hits", len(hits), [hex(ib+va+h) for h in hits[:10]])
for h in hits[:3]:
    print(f"\n==== at {ib+va+h:#x} ====")
    for insn in md.disasm(code[h-0x20:h+0x30], ib+va+h-0x20):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# also find pop rbx; pop rdi; pop rsi; leave; ret
epi=bytes.fromhex("5b5f5ec9c3")
idx=0; epis=[]
while True:
    j=code.find(epi, idx)
    if j<0: break
    epis.append(j); idx=j+1
print("\nepi pop rbx/rdi/rsi/leave/ret count", len(epis))
