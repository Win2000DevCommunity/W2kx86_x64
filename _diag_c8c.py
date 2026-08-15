import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
base = struct.unpack_from("<I", src, e+24+28)[0]
secs = []
for i in range(num):
    o = sec+i*40
    name = src[o:o+8].split(b"\x00")[0].decode()
    vs,va,rs,rp = struct.unpack_from("<IIII", src, o+8)
    secs.append((name,va,vs,rs,rp))

for name,va,vs,rs,rp in secs:
    if name==".data":
        off = 0x1c8d8 - va
        print(f".data off for c8d8: {off:#x}")
        if 0 <= off < rs:
            print("init", src[rp+off:rp+off+16].hex())
        else:
            print("BSS (beyond raw rs)")
        # dump neighborhood of initialized .data around 0x8d8 if in raw
        if off < rs:
            print("around:", src[rp+off-16:rp+off+32].hex())

# Find ALL absolute memory destinations in .text to 0x4ad1xxxx
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
for name,va,vs,rs,rp in secs:
    if name==".text":
        text=src[rp:rp+rs]; text_rva=va; break

print("\n=== Absolute stores (dst=mem abs) in .text to .data range ===")
stores=[]
for insn in md.disasm(text, base+text_rva):
    if not insn.operands: continue
    # destination is first operand for most
    op0 = insn.operands[0]
    if op0.type != 3: continue  # MEM
    if op0.mem.base != 0 or op0.mem.index != 0: continue
    d = op0.mem.disp & 0xffffffff
    if not (0x4ad1c000 <= d <= 0x4ad29000): continue
    if insn.mnemonic not in ("mov","movzx","movsx","xchg","add","sub","or","and","xor","inc","dec","not","neg","lea"):
        # lea doesn't store
        pass
    if insn.mnemonic == "lea": continue
    # filter true stores: mnemonic typically mov with mem dest
    if insn.mnemonic.startswith("mov") or insn.mnemonic in ("xchg","add","sub","or","and","xor","inc","dec"):
        stores.append((insn.address-base, d, f"{insn.mnemonic} {insn.op_str}"))

print(f"found {len(stores)} abs stores to .data")
# group by address
from collections import Counter
c = Counter(d for _,d,_ in stores)
print("top targets:")
for d,n in c.most_common(30):
    print(f"  {d:#x} x{n}")
print("c8d8 in store targets?", 0x4ad1c8d8 in c)

# Show stores near c8d8 (?0x100)
print("\nstores near c8d8:")
for a,d,s in stores:
    if abs(d - 0x4ad1c8d8) < 0x100:
        print(f"  {a:#07x}: [{d:#x}] {s}")

# Relocs: parse base reloc looking for page+offset that hits 0x1c8d8
print("\n=== Relocs targeting RVA 0x1c8d8 (value written TO that addr via reloc? no - reloc patches CODE that CONTAINS the abs addr) ===")
# Actually IMAGE_REL_BASED_HIGHLOW patches the absolute address IN CODE/DATA. So if something STORES the address of a buffer INTO c8d8, the reloc would be on the IMMEDIATE in the store instruction, not on c8d8 itself.
# If c8d8 is in a reloc as a LOCATION being fixed up, that means the DWORD AT c8d8 contains an absolute address that needs rebasing - i.e. it was INITIALIZED in the file with a pointer!

print("Check if RVA 0x1c8d8 appears as reloc TARGET (fixup location):")
# DataDirectory[5] base reloc
dd = e + 24 + 96 + 5*8  # optional header PE32: magic at 24, DD at 24+96
# Actually PE32 optional: 28-byte standard + 68 windows + DD. DD starts at e+24+96 = e+120
rva_rel, sz_rel = struct.unpack_from("<II", src, e+120+5*8)
print(f"reloc dir rva={rva_rel:#x} sz={sz_rel:#x}")

def file_of(rva):
    for name,va,vs,rs,rp in secs:
        if va <= rva < va+max(vs,rs):
            return rp + (rva-va)
    return None

fo = file_of(rva_rel)
hits=[]
if fo is not None:
    end = fo + sz_rel
    p = fo
    while p+8 <= end:
        page, size = struct.unpack_from("<II", src, p)
        if size < 8: break
        for q in range(p+8, p+size, 2):
            ent = struct.unpack_from("<H", src, q)[0]
            typ, off = ent>>12, ent&0xfff
            if typ==0: continue
            loc = page+off
            if loc == 0x1c8d8 or abs(loc-0x1c8d8)<4:
                hits.append((loc, typ))
        p += size
print("reloc hits near c8d8:", hits)

# If c8d8 is BSS and never stored - maybe the POINTER is supposed to be set by code that uses
# a different encoding. Search for 8D 05 (lea eax, [imm]) of buffers then mov [something]
# Or look at GetCommandLineW callers
print("\n=== Find IAT slot for GetCommandLineW ===")
# Import: find thunk. Parse imports roughly
imp_rva, imp_sz = struct.unpack_from("<II", src, e+120+1*8)
print(f"import dir {imp_rva:#x}")
p = file_of(imp_rva)
while True:
    ilt,_,_,name_rva,iat = struct.unpack_from("<IIIII", src, p)
    if ilt==0 and name_rva==0: break
    dll = src[file_of(name_rva):].split(b"\x00")[0]
    # walk IAT
    k=0
    while True:
        hint_rva = struct.unpack_from("<I", src, file_of(iat)+k*4)[0]
        if hint_rva==0: break
        if hint_rva & 0x80000000:
            name="ord"
        else:
            nm = src[file_of(hint_rva)+2:].split(b"\x00")[0]
            if nm == b"GetCommandLineW":
                print(f"  {dll}: GetCommandLineW IAT RVA={iat+k*4:#x} VA={base+iat+k*4:#x}")
                iat_va = base+iat+k*4
                # find call [iat_va] or mov reg,[iat]
                pat = struct.pack("<I", iat_va)
                idx=0
                while True:
                    j=text.find(pat, idx)
                    if j<0: break
                    rva=text_rva+j
                    # back up to see opcode
                    print(f"    ref at {rva:#x} bytes {text[j-2:j+4].hex()}")
                    # disasm around
                    for insn in md.disasm(text[max(0,j-16):j+24], base+text_rva+max(0,j-16), count=12):
                        print(f"      {insn.address-base:#07x} {insn.mnemonic} {insn.op_str}")
                    idx=j+1
        k+=1
    p += 20
