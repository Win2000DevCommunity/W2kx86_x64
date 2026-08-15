import os, pathlib, struct, shutil, sys
sys.path.insert(0, ".")
os.environ["PURE"] = "1"
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator
from tools.audit_calls import load_map, read_text_section

src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe = PE32Image(src.read_bytes())
raw = bytearray(pathlib.Path("build_fix2/cmd_pure.exe").read_bytes())
trva, data, new_base = read_text_section(bytes(raw))
peoff = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, peoff+6)[0]
opt = struct.unpack_from("<H", raw, peoff+20)[0]
sec = peoff+24+opt
rptr = next(struct.unpack_from("<I", raw, sec+i*40+20)[0]
            for i in range(n)
            if struct.unpack_from("<I", raw, sec+i*40+36)[0] & 0x20000000)

t = Win2000Translator(pe, win10_test_shim=True, source_path=str(src))
t.new_base = new_base
t._cmd_no_hacks = True
t._is_alloca_probe_rva = lambda r: False
layout = {".text": 0x1000, ".data": 0x5c000, ".rsrc": 0x6a000}
t._old_to_new_section = {s["vaddr"]: layout[s["name"].rstrip("\0").lower()]
                         for s in pe.sections
                         if s["name"].rstrip("\0").lower() in layout}
rmap_abs = load_map(pathlib.Path("build_fix2/rva.txt"))
text_rmap = {k: v-trva for k,v in rmap_abs.items() if v >= trva}
t.rva_map = dict(text_rmap)
secobj, text_data = pe.get_text_section()
out = bytearray(data)
# reconcile entries then sync
n1 = t._pure_reconcile_swallowed_rva_map(out, text_rmap, text_data, secobj.vaddr)
n2 = t._pure_authoritative_x86_call_sync(out, text_rmap, text_data, secobj.vaddr)
print(f"reconcile={n1} sync={n2}")
# check command-loop call sites in x64 around 0x16727
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("loop region:")
for ins in md.disasm(bytes(out[0x16720-trva:0x16720-trva+90]), 0x16720):
    mark = ""
    if ins.mnemonic == "call":
        mark = " <<<"
    print(f"  {ins.address:#07x}  {ins.bytes.hex():<18} {ins.mnemonic} {ins.op_str}{mark}")
raw[rptr:rptr+len(out)] = out
pathlib.Path("build_exp").mkdir(exist_ok=True)
pathlib.Path("build_exp/cmd_pure.exe").write_bytes(bytes(raw))
shutil.copy2("build_fix2/w2kshim64.dll", "build_exp/w2kshim64.dll")
print("wrote build_exp")
