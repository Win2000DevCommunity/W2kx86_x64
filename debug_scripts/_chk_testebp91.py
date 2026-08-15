from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

root = Path(r"c:\Users\win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\X86_X64")
pe_path = root / "build_univ91" / "cmd_pure.exe"
rmap_path = root / "build_univ91" / "rva.txt"

rmap = {}
for ln in rmap_path.read_text().splitlines():
    a, b = ln.split()[:2]
    rmap[int(a, 16)] = int(b, 16)

x86 = 0xAE32
pe64_rva = rmap[x86]
print(f"x86 {x86:#x} -> pe64 RVA {pe64_rva:#x}")

data = pe_path.read_bytes()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + opt_size
text_va = text_raw = None
for i in range(num_sec):
    off = sec_off + i * 40
    name = data[off:off + 8].split(b"\0", 1)[0]
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, off + 8)
    if name == b".text":
        text_va, text_raw = va, raw
        break
file_off = text_raw + (pe64_rva - text_va)
blob = data[file_off:file_off + 48]
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("bytes:", blob[:16].hex())
for insn in md.disasm(blob, 0x80000000 + pe64_rva):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x80000000 + pe64_rva + 20:
        break

bad = blob[:3] in (bytes.fromhex("4889d0"), bytes.fromhex("4889D0"))
good_home = blob.startswith(b"\xf6\x45\x18\x21")
good_dl = blob.startswith(b"\xf6\xc2\x21")
print("BAD mov rax,rdx:", bad)
print("OK test form:", good_home or good_dl, "home" if good_home else ("dl" if good_dl else "NO"))

# Also check A3 22844 store near adad and getchar cursor
for label, xa in [("and fbe2", 0xADA5), ("mov 22844", 0xAE44), ("getchar CR", 0xAC92)]:
    r = rmap.get(xa)
    print(f"{label}: x86 {xa:#x} -> {r and hex(r)}")
