import struct
from pathlib import Path
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SRC = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe = PE32Image(SRC.read_bytes())
tr = Win2000Translator(pe, win10_test_shim=True, source_path=str(SRC))
tr._cmd_no_hacks = True

raw = bytearray(Path("build_univ12/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", raw, 0x3c)[0]
num = struct.unpack_from("<H", raw, e + 6)[0]
soh = struct.unpack_from("<H", raw, e + 20)[0]
sec = e + 24 + soh
for i in range(num):
    o = sec + i * 40
    name = raw[o:o + 8].split(b"\0")[0]
    if name.startswith(b".text"):
        va, vsz, rs, rp = struct.unpack_from("<IIII", raw, o + 8)
        blob = bytearray(raw[rp:rp + rs])
        n = tr._fix_arg_select_lea_selfjmp(blob)
        print("arg-select fixed", n)
        # leave other self-jmps alone
        raw[rp:rp + rs] = blob
        Path("build_univ12/cmd_pure_h2.exe").write_bytes(raw)
        break

trva, data, _ = read_text_section(Path("build_univ12/cmd_pure_h2.exe").read_bytes())
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("selfjmps left", sum(1 for i in range(len(data)-5)
    if data[i]==0xE9 and data[i+1:i+5]==b"\xfb\xff\xff\xff"))
for insn in md.disasm(data[0x7700-trva:0x7730-trva], 0x7700, count=8):
    print(f"  {insn.address:#07x}  {insn.mnemonic} {insn.op_str}")
