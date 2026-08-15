# Test: ecx+gle1+exitw+set SingleCommand when sticky written to 1 in PEB helper
# Find in pure: mov [sticky],1 pattern near seed and also write SingleCommand
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
print("wexit", t._pure_fix_peb_c_infinite_waiter_exits(blob))

# Also patch: after sticky=1 store, set SingleCommand=1
# Pattern: 49 bb <sticky> ; 41 c7 03 01 00 00 00
sc = 0x80058F64
sticky_imm = None
for k in range(len(blob)-20):
    if blob[k:k+2]==b"\x49\xbb":
        v=struct.unpack_from("<Q", blob, k+2)[0]
        if (v&0xFFFF)==0xBE00 and blob[k+10:k+17]==bytes.fromhex("41c70301000000"):
            sticky_imm=v
            print("sticky=1 at", hex(k+0x1000), "va", hex(v))
            # insert after: movabs rax, sc; mov dword [rax],1 via cave
            # replace the 7-byte mov with jmp cave that does both
            store_at = k+10
            stub=bytearray()
            stub += bytes.fromhex("41c70301000000")  # sticky=1
            stub += b"\x48\xb8"+struct.pack("<Q", sc)
            stub += b"\xc7\x00\x01\x00\x00\x00"  # mov dword [rax],1
            stub += b"\xe9"+struct.pack("<i",0)
            cave=t._pure_find_padding_cave(blob, len(stub)+4)
            if cave<0:
                cave=len(blob); blob.extend(b"\x00"*(len(stub)+8))
            fall=store_at+7
            struct.pack_into("<i", stub, len(stub)-4, fall-(cave+len(stub)))
            blob[cave:cave+len(stub)]=stub
            blob[store_at:store_at+7]=b"\xe9"+struct.pack("<i", cave-(store_at+5))+b"\x90\x90"
            print("patched SingleCommand at sticky=1, cave", hex(cave+0x1000))
            break

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
outp=pathlib.Path("build_univ257/cmd_probe_univ.exe")
outp.write_bytes(out)
print("wrote", outp)

p=subprocess.Popen([sys.executable,"dbg_fault.py",str(outp),"/c","echo","w2ktest"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    data,_=p.communicate(timeout=12); status=f"DONE exit={p.returncode}"
except subprocess.TimeoutExpired:
    p.kill(); data,_=p.communicate(); status="TIMEOUT"
print(status)
print(data.decode("utf-8","replace").encode("ascii","replace").decode()[:1500])
