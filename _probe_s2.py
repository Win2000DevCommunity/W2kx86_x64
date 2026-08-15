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

sticky=0x8005BE00; term=0x800845E0

# 1) Echo success epi 428D2: 5f 48 31 c0 5e c3 ? bump sticky 1?2 then original
epi=bytes.fromhex("5f4831c05ec3")
# only the one near echo (after jmp from 427fb) ? search all and pick ones preceded by add rsp,8 or jmp land
at=0x428D2-0x1000
assert blob[at:at+6]==epi, blob[at:at+6].hex()
stub=bytearray()
stub += b"\x49\xbb"+struct.pack("<Q", sticky)
stub += b"\x41\x83\x3b\x01"  # cmp [r11],1
stub += b"\x75\x07"          # jne +7
stub += b"\x41\xc7\x03\x02\x00\x00\x00"  # sticky=2
stub += epi
stub += b"\xe9"+struct.pack("<i",0)  # not needed - epi has ret
# epi ends with ret - no jmp back. Replace epi with jmp cave.
cave=t._pure_find_padding_cave(blob, len(stub)+4)
if cave<0: cave=len(blob); blob.extend(b"\x00"*(len(stub)+8))
blob[cave:cave+len(stub)]=stub
blob[at:at+6]=b"\xe9"+struct.pack("<i", cave-(at+5))+b"\x90"
print("echo epi -> sticky bump cave", hex(cave+0x1000))

# 2) 1EA3C: if sticky>=2 exit else homes
off=0x1EA3C-0x1000
homes=bytes.fromhex("48894c240848895424104c894424184c894c2420")
stub2=bytearray()
stub2 += b"\x49\xbb"+struct.pack("<Q", sticky)
stub2 += b"\x41\x83\x3b\x02"  # cmp [r11],2
stub2 += b"\x72\x18"          # jb +24 (sticky < 2)
stub2 += b"\x31\xd2"
stub2 += b"\x48\xc7\xc1\xff\xff\xff\xff"
stub2 += b"\x48\xb8"+struct.pack("<Q", term)
stub2 += b"\x48\x8b\x00\xff\xe0"
stub2 += homes
stub2 += b"\xe9"+struct.pack("<i",0)
cave2=t._pure_find_padding_cave(blob, len(stub2)+4)
if cave2<0: cave2=len(blob); blob.extend(b"\x00"*(len(stub2)+8))
fall=off+20
struct.pack_into("<i", stub2, len(stub2)-4, fall-(cave2+len(stub2)))
blob[cave2:cave2+len(stub2)]=stub2
blob[off:off+20]=b"\xe9"+struct.pack("<i", cave2-(off+5))+b"\x90"*15
print("1EA3C sticky>=2 exit cave", hex(cave2+0x1000))

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
outp=pathlib.Path("build_univ257/cmd_probe_s2.exe")
outp.write_bytes(out)

p=subprocess.Popen([sys.executable,"dbg_fault.py",str(outp),"/c","echo","w2ktest"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    data,_=p.communicate(timeout=12); status=f"DONE exit={p.returncode}"
except subprocess.TimeoutExpired:
    p.kill(); data,_=p.communicate(); status="TIMEOUT"
print(status)
print(data.decode("utf-8","replace").encode("ascii","replace").decode()[:1500])
