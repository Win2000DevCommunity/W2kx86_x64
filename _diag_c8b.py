import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
base = struct.unpack_from("<I", src, e+24+28)[0]
print("image base", hex(base))
secs = []
for i in range(num):
    o = sec+i*40
    name = src[o:o+8].split(b"\x00")[0].decode()
    vs,va,rs,rp = struct.unpack_from("<IIII", src, o+8)
    secs.append((name,va,vs,rs,rp))
    print(f"  {name:8} VA={va:#x} VS={vs:#x} RS={rs:#x} RP={rp:#x}")

def rva_of(file_off):
    for name,va,vs,rs,rp in secs:
        if rp and rp <= file_off < rp+rs:
            return name, va+(file_off-rp)
    return "?", None

needle = struct.pack("<I", 0x4ad1c8d8)
print("\nAll refs to 0x4ad1c8d8:")
stores = []
loads = []
i = 0
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
text=None; text_rva=None; text_rp=None
for name,va,vs,rs,rp in secs:
    if name==".text":
        text=src[rp:rp+rs]; text_rva=va; text_rp=rp; break

while True:
    j = src.find(needle, i)
    if j < 0: break
    sn, rva = rva_of(j)
    # look at opcode byte before the imm
    opb = src[j-1]
    kind = "?"
    # classify common patterns
    if opb == 0xA1: kind="LOAD mov eax,[m]"
    elif opb == 0xA3: kind="STORE mov [m],eax"
    elif opb == 0x05 and src[j-2]==0x89: kind="STORE mov [m],eax"
    elif opb == 0x0D and src[j-2]==0x89: kind="STORE mov [m],ecx"
    elif opb == 0x15 and src[j-2]==0x89: kind="STORE mov [m],edx"
    elif opb == 0x1D and src[j-2]==0x89: kind="STORE mov [m],ebx"
    elif opb == 0x25 and src[j-2]==0x89: kind="STORE mov [m],esp"
    elif opb == 0x2D and src[j-2]==0x89: kind="STORE mov [m],ebp"
    elif opb == 0x35 and src[j-2]==0x89: kind="STORE mov [m],esi"
    elif opb == 0x3D and src[j-2]==0x89: kind="STORE mov [m],edi"
    elif opb == 0x05 and src[j-2]==0x8B: kind="LOAD mov eax,[m]"
    elif opb == 0x0D and src[j-2]==0x8B: kind="LOAD mov ecx,[m]"
    elif opb == 0x15 and src[j-2]==0x8B: kind="LOAD mov edx,[m]"
    elif opb == 0x35 and src[j-2]==0xFF: kind="LOAD push [m]"
    elif opb == 0x05 and src[j-2]==0xC7: kind="STORE mov [m],imm"
    elif opb == 0x05 and src[j-2]==0x83: kind="RMW [m]"
    else:
        kind=f"op={src[j-2]:02x}{opb:02x}"
    rec = (sn, rva, kind, src[j-4:j+4].hex())
    if "STORE" in kind:
        stores.append(rec)
    else:
        loads.append(rec)
    i = j+1

print(f"loads={len(loads)} stores={len(stores)}")
print("STORES:")
for s in stores[:40]:
    print(" ", s)
print("sample loads:")
for s in loads[:8]:
    print(" ", s)

# .data content at c8d8
for name,va,vs,rs,rp in secs:
    if name==".data":
        off = 0xc8d8 - va
        print(f"\n.data: va={va:#x} vs={vs:#x} rs={rs:#x}")
        print(f"c8d8 off into section={off:#x} ({off})")
        if 0 <= off < rs:
            print("init bytes", src[rp+off:rp+off+16].hex())
        elif 0 <= off < vs:
            print("BSS zero-init (beyond raw)")
        else:
            print("OUT OF SECTION?")

# Find GetCommandLineW IAT and callers
print("\n=== GetCommandLineW IAT usage ===")
# find import name
idx = src.find(b"GetCommandLineW\x00")
print("name at", hex(idx))
# Find IAT slot by scanning for call [imm] patterns after finding thunk
# In PE, look at import directory
# Simpler: disasm all call dword ptr [imm] and see which resolve to GetCommandLine

# Search for mov [global], eax shortly after GetCommandLine call
# Common CRT pattern at startup
print("\n=== Search nearby globals that ARE stored (c8xx range) ===")
# Find all absolute stores in .text to 0x4ad1c000-0x4ad1d000
store_count = {}
for insn in md.disasm(text, base+text_rva):
    if not insn.operands: continue
    for oi,op in enumerate(insn.operands):
        if op.type == 3 and op.mem.base==0 and op.mem.index==0:
            d = op.mem.disp & 0xffffffff
            if 0x4ad1c000 <= d <= 0x4ad1d000:
                is_dst = (oi==0 and insn.mnemonic.startswith("mov"))
                if is_dst or insn.mnemonic in ("xchg",) or (insn.mnemonic.startswith("mov") and oi==0):
                    key = (d, insn.mnemonic)
                    store_count[key] = store_count.get(key,0)+1
                    if d == 0x4ad1c8d8:
                        print(f"STORE HIT {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")

print("stores in c000-d000:")
for (d,m),c in sorted(store_count.items()):
    print(f"  {d:#x} {m} x{c}")
