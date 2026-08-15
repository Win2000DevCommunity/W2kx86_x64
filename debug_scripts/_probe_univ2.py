import struct, pathlib, subprocess, sys
from x86x64.translator._healing import HealingMixin
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

class T(HealingMixin):
    pass

src = pathlib.Path("build_univ257/cmd_pure.exe")
pe_bytes = bytearray(src.read_bytes())
e = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
ns = struct.unpack_from("<H", pe_bytes, e + 6)[0]
so = struct.unpack_from("<H", pe_bytes, e + 20)[0]
sec = e + 24 + so
fa = struct.unpack_from("<I", pe_bytes, e + 24 + 36)[0]

sections = []
for i in range(ns):
    o = sec + i * 40
    name = pe_bytes[o:o+8].split(b"\0")[0].decode("ascii", "replace")
    vs, va, rs, rp = struct.unpack_from("<IIII", pe_bytes, o + 8)
    sections.append({"o": o, "name": name, "vs": vs, "va": va, "rs": rs, "rp": rp})

text = next(s for s in sections if s["name"] == ".text")
blob = bytearray(pe_bytes[text["rp"]:text["rp"] + text["rs"]])

t = T(); t._cmd_no_hacks = True; t._pure_cave_cursor = 0; t.new_base = 0x80000000
ppe = pefile.PE(data=bytes(pe_bytes))
t._iat_name_to_new_rva = {}
for exp in ppe.DIRECTORY_ENTRY_IMPORT:
    for imp in exp.imports:
        if imp.name and imp.address:
            t._iat_name_to_new_rva[(exp.dll.decode(errors="replace"),
                                    imp.name.decode(errors="replace"))] = (
                imp.address - 0x80000000)

print("ecx", t._pure_fix_missing_push_ecx_local_before_csr(blob))
print("gle1", t._pure_fix_stale_getlasterror_exitprocess1(blob))
print("exitw", t._pure_fix_exitprocess_wrapper_via_terminate(blob))
print("wexit", t._pure_fix_peb_c_infinite_waiter_exits(blob))

new_rs = (len(blob) + fa - 1) & ~(fa - 1)
blob_padded = bytes(blob) + b"\x00" * (new_rs - len(blob))
print("blob", len(blob), "new_rs", new_rs)

sec_data = {}
for s in sections:
    if s["name"] == ".text":
        sec_data[s["name"]] = blob_padded
        s["rs"] = new_rs
        s["vs"] = max(s["vs"], len(blob))
    else:
        sec_data[s["name"]] = bytes(pe_bytes[s["rp"]:s["rp"] + s["rs"]])

hdr_end = min(s["rp"] for s in sections)
file_ptr = hdr_end
for s in sections:
    s["rp"] = file_ptr
    file_ptr += s["rs"]

out = bytearray(pe_bytes[:hdr_end])
for s in sections:
    struct.pack_into("<I", out, s["o"] + 8, s["vs"])
    struct.pack_into("<I", out, s["o"] + 16, s["rs"])
    struct.pack_into("<I", out, s["o"] + 20, s["rp"])
for s in sections:
    if len(out) < s["rp"]:
        out.extend(b"\x00" * (s["rp"] - len(out)))
    out.extend(sec_data[s["name"]])

outp = pathlib.Path("build_univ257/cmd_probe_univ.exe")
outp.write_bytes(out)
print("wrote", outp, "size", len(out))

ppe2 = pefile.PE(str(outp))
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== waiter ===")
for i in md.disasm(ppe2.get_data(0x4581E, 0x40), 0x8004581E):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
# follow jmp
b = ppe2.get_data(0x45832, 5)
if b[0] == 0xE9:
    rel = struct.unpack_from("<i", b, 1)[0]
    cave = 0x45832 + 5 + rel
    print("cave", hex(cave))
    for i in md.disasm(ppe2.get_data(cave, 0x50), 0x80000000 + cave):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

p = subprocess.Popen([sys.executable, "dbg_fault.py", str(outp), "/c", "echo", "w2ktest"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    data, _ = p.communicate(timeout=15)
    status = f"DONE exit={p.returncode}"
except subprocess.TimeoutExpired:
    p.kill(); data, _ = p.communicate(); status = "TIMEOUT"
print(status)
print(data.decode("utf-8", "replace").encode("ascii", "replace").decode()[:2000])
