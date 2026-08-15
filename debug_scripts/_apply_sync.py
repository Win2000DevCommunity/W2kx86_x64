import os, pathlib, struct, shutil, sys
sys.path.insert(0, '.')
os.environ["PURE"] = "1"
from x86x64.pe import PE32Image, validate_pe
from x86x64.translator import Win2000Translator
from tools.audit_calls import load_map, read_text_section, disassemble

src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
exe = pathlib.Path("build_fix2/cmd_pure.exe")
pe = PE32Image(src.read_bytes())
raw = bytearray(exe.read_bytes())
trva, data, new_base = read_text_section(bytes(raw))
peoff = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, peoff+6)[0]
opt = struct.unpack_from("<H", raw, peoff+20)[0]
sec = peoff+24+opt
rptr = None
for i in range(n):
    off = sec+i*40
    flags = struct.unpack_from("<I", raw, off+36)[0]
    if flags & 0x20000000:
        rptr = struct.unpack_from("<I", raw, off+20)[0]
        break

t = Win2000Translator(pe, win10_test_shim=True, source_path=str(src))
t.new_base = new_base
t._cmd_no_hacks = True
t._is_alloca_probe_rva = lambda r: False
layout = {".text": 0x1000, ".data": 0x5c000, ".rsrc": 0x6a000}
t._old_to_new_section = {}
for s in pe.sections:
    name = s["name"].rstrip("\0").lower()
    if name in layout:
        t._old_to_new_section[s["vaddr"]] = layout[name]
rmap_abs = load_map(pathlib.Path("build_fix2/rva.txt"))
text_rmap = {k: v-trva for k,v in rmap_abs.items() if v >= trva}
t.rva_map = dict(text_rmap)
secobj, text_data = pe.get_text_section()
out = bytearray(data)
n1 = t._pure_reconcile_swallowed_rva_map(out, text_rmap, text_data, secobj.vaddr)
n2 = t._pure_authoritative_x86_call_sync(out, text_rmap, text_data, secobj.vaddr)
n3 = t._pure_repair_all_align_stub_calls(out, text_rmap, text_data, secobj.vaddr)
print(f"reconcile={n1} sync={n2} align_repair={n3}")
raw[rptr:rptr+len(out)] = out
pathlib.Path("build_exp").mkdir(exist_ok=True)
pathlib.Path("build_exp/cmd_pure.exe").write_bytes(bytes(raw))
shutil.copy2("build_fix2/w2kshim64.dll", "build_exp/w2kshim64.dll")
report = validate_pe(bytes(raw))
print("validator", "ok" if report.ok else report)
mapped = set(text_rmap.values())
insns = disassemble(bytes(out), 0, mapped)
starts = {i.address for i in insns}|mapped
bad=0; total=0
for ins in insns:
    if out[ins.address]!=0xE8 or ins.size!=5: continue
    total+=1
    rel=struct.unpack_from("<i", out, ins.address+1)[0]
    tgt=ins.address+5+rel
    if 0<=tgt<len(out) and tgt not in starts: bad+=1
print(f"calls={total} bad_mid={bad}")
cur = 0x130e7-trva
tgt = cur+5+struct.unpack_from("<i", out, cur+1)[0]
print(f"getenv call -> {tgt+trva:#x}")
