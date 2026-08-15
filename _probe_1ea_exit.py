import struct, pathlib, subprocess, sys
from x86x64.translator._healing import HealingMixin
import pefile

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
    name = pe_bytes[o:o+8].split(b"\0")[0].decode("ascii","replace")
    vs,va,rs,rp = struct.unpack_from("<IIII", pe_bytes, o+8)
    sections.append({"o":o,"name":name,"vs":vs,"va":va,"rs":rs,"rp":rp})
text = next(s for s in sections if s["name"]==".text")
blob = bytearray(pe_bytes[text["rp"]:text["rp"]+text["rs"]])
t=T(); t._cmd_no_hacks=True; t._pure_cave_cursor=0; t.new_base=0x80000000
ppe=pefile.PE(data=bytes(pe_bytes))
t._iat_name_to_new_rva={}
for exp in ppe.DIRECTORY_ENTRY_IMPORT:
    for imp in exp.imports:
        if imp.name and imp.address:
            t._iat_name_to_new_rva[(exp.dll.decode(errors="replace"), imp.name.decode(errors="replace"))]=imp.address-0x80000000

print("ecx", t._pure_fix_missing_push_ecx_local_before_csr(blob))
print("gle1", t._pure_fix_stale_getlasterror_exitprocess1(blob))
print("exitw", t._pure_fix_exitprocess_wrapper_via_terminate(blob))
# Skip broken wexit for now ? patch 1EA3C entry instead
# Pattern at 1EA3C: homes 48894c2408...
off = 0x1EA3C - 0x1000
homes = bytes.fromhex("48894c240848895424104c894424184c894c2420")
assert blob[off:off+20]==homes, blob[off:off+20].hex()
sticky=0x8005BE00; term=0x800845E0
stub=bytearray()
stub += b"\x49\xbb"+struct.pack("<Q", sticky)
stub += b"\x41\x83\x3b\x00"
stub += b"\x74\x18"
stub += b"\x31\xd2"
stub += b"\x48\xc7\xc1\xff\xff\xff\xff"
stub += b"\x48\xb8"+struct.pack("<Q", term)
stub += b"\x48\x8b\x00\xff\xe0"
# fallthrough: original homes then jmp back after homes
stub += homes
stub += b"\xe9"+struct.pack("<i", 0)
cave=t._pure_find_padding_cave(blob, len(stub)+4)
if cave<0:
    cave=len(blob); blob.extend(b"\x00"*(len(stub)+8))
fall=off+20
struct.pack_into("<i", stub, len(stub)-4, fall-(cave+len(stub)))
blob[cave:cave+len(stub)]=stub
blob[off:off+20]=b"\xe9"+struct.pack("<i", cave-(off+5))+b"\x90"*15
print("patched 1EA3C -> cave", hex(cave+0x1000))

new_rs=(len(blob)+fa-1)&~(fa-1)
blob_padded=bytes(blob)+b"\x00"*(new_rs-len(blob))
sec_data={}
for s in sections:
    if s["name"]==".text":
        sec_data[s["name"]]=blob_padded; s["rs"]=new_rs; s["vs"]=max(s["vs"],len(blob))
    else:
        sec_data[s["name"]]=bytes(pe_bytes[s["rp"]:s["rp"]+s["rs"]])
hdr_end=min(s["rp"] for s in sections)
fp=hdr_end
for s in sections:
    s["rp"]=fp; fp+=s["rs"]
out=bytearray(pe_bytes[:hdr_end])
for s in sections:
    struct.pack_into("<I", out, s["o"]+8, s["vs"])
    struct.pack_into("<I", out, s["o"]+16, s["rs"])
    struct.pack_into("<I", out, s["o"]+20, s["rp"])
for s in sections:
    if len(out)<s["rp"]: out.extend(b"\x00"*(s["rp"]-len(out)))
    out.extend(sec_data[s["name"]])
outp=pathlib.Path("build_univ257/cmd_probe_1ea.exe")
outp.write_bytes(out)

p=subprocess.Popen([sys.executable,"dbg_fault.py",str(outp),"/c","echo","w2ktest"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    data,_=p.communicate(timeout=12); status=f"DONE exit={p.returncode}"
except subprocess.TimeoutExpired:
    p.kill(); data,_=p.communicate(); status="TIMEOUT"
print(status)
print(data.decode("utf-8","replace").encode("ascii","replace").decode()[:1500])
