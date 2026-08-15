import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = bytearray(pathlib.Path("build_univ227/cmd_univ9.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
# parse imports
export_dir = None
# DataDirectory[1] = imports
dd = e + 24 + 112  # optional header magic PE32+ 
# actually for PE32+: standard fields 24 bytes after magic, then 112 for dirs? 
# COFF + magic(2) + 22 major/minor linker etc... use known approach
opt = e + 24
magic = struct.unpack_from("<H", pe, opt)[0]
print("magic", hex(magic))
if magic == 0x20b:
    dd0 = opt + 112
else:
    dd0 = opt + 96
imp_rva, imp_sz = struct.unpack_from("<II", pe, dd0 + 8)

def rva_to_off(rva):
    for i in range(ns):
        o = sec+i*40
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8)
        if va <= rva < va+max(vs,rs):
            return rp + (rva - va)
    return None

# walk import descriptors
off = rva_to_off(imp_rva)
names = {}
while True:
    ilt,_,_,name_rva,iat = struct.unpack_from("<IIIII", pe, off)
    if ilt == 0 and name_rva == 0:
        break
    dll = pe[rva_to_off(name_rva):].split(b"\0",1)[0].decode()
    # walk IAT
    j = 0
    while True:
        slot_rva = iat + j*8
        thunk = struct.unpack_from("<Q", pe, rva_to_off(slot_rva))[0]
        if thunk == 0:
            break
        if thunk & (1<<63):
            nm = f"ordinal#{thunk & 0xffff}"
        else:
            hint_rva = thunk & 0x7fffffff
            nm = pe[rva_to_off(hint_rva)+2:].split(b"\0",1)[0].decode(errors="replace")
        names[slot_rva] = (dll, nm)
        j += 1
    off += 20

for slot in (0x84658, 0x85430):
    print(hex(slot), names.get(slot, "?"), "val would be at", hex(ib+slot))

# disasm 17760..177a0 and 17a60
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
blob=pe[rp:rp+rs]
print("=== 17760 ===")
for insn in md.disasm(bytes(blob[0x17760-va:0x177a0-va]), ib+0x17760):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
print("=== 17a60 ===")
for insn in md.disasm(bytes(blob[0x17a60-va:0x17a90-va]), ib+0x17a60):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
