from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct

root = Path(r"c:\Users\win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\X86_X64")
pe_path = root / "build_univ91" / "cmd_pure.exe"
rmap_path = root / "build_univ91" / "rva.txt"
src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")

rmap = {}
for ln in rmap_path.read_text().splitlines():
    a, b = ln.split()[:2]
    rmap[int(a, 16)] = int(b, 16)

def pe_text(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e+6)[0]
    osz = struct.unpack_from("<H", data, e+20)[0]
    soff = e+24+osz
    for i in range(nsec):
        off = soff+i*40
        name = data[off:off+8].split(b"\0",1)[0]
        vsz,va,rsz,raw = struct.unpack_from("<IIII", data, off+8)
        if name==b".text":
            return va, raw, rsz
    raise SystemExit("no .text")

data32 = src.read_bytes()
va32, raw32, _ = pe_text(data32)
base32 = 0x4ad00000
fo = raw32 + (0xadad - va32)
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 from 0xadad ===")
for insn in md32.disasm(data32[fo:fo+0x100], base32+0xadad):
    mark = " <<<" if insn.address == base32+0xae32 else ""
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}{mark}")
    if insn.address >= base32+0xae70:
        break

data64 = pe_path.read_bytes()
va64, raw64, _ = pe_text(data64)
base64 = 0x80000000
entry = 0x14620
fo64 = raw64 + (entry - va64)
md64 = Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== pe64 from 0x14620 (adad) ===")
for insn in md64.disasm(data64[fo64:fo64+0x200], base64+entry):
    s = f"{insn.mnemonic} {insn.op_str}"
    mark = ""
    if "test" in insn.mnemonic and ("0x21" in insn.op_str or "rbp" in insn.op_str or "dl" in insn.op_str or "edx" in insn.op_str):
        mark = " <<<"
    if "mov rax, rdx" in s or s == "mov rax, rdx":
        mark = " !!! BAD"
    print(f"  {insn.address:#x}: {s}{mark}")
    if insn.address >= base64+0x147a0:
        break

# specifically search for test byte [rbp+18], 0x21 or mov rax,rdx near here
blob = data64[fo64:fo64+0x200]
idx = 0
while True:
    i = blob.find(b"\xf6\x45\x18\x21", idx)
    if i < 0: break
    print(f"FOUND test [rbp+0x18],0x21 at RVA {entry+i:#x}")
    idx = i+1
idx = 0
while True:
    i = blob.find(b"\x48\x89\xd0", idx)
    if i < 0: break
    print(f"FOUND mov rax,rdx at RVA {entry+i:#x}")
    idx = i+1
idx = 0
while True:
    i = blob.find(b"\xf6\xc2\x21", idx)
    if i < 0: break
    print(f"FOUND test dl,0x21 at RVA {entry+i:#x}")
    idx = i+1
