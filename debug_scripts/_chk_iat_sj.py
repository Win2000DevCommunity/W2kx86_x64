from pathlib import Path
import struct
from tools.audit_calls import read_text_section

# Read PE imports for univ14 - find _setjmp3 thunk VA
raw = Path("build_univ14/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", raw, 0x3c)[0]
# PE32+ optional header
magic = struct.unpack_from("<H", raw, e+24)[0]
print("magic", hex(magic))
# DataDirectory import at optional+112 for PE32+
# COFF header size 20, optional starts e+24
oh = e + 24
dd_import = struct.unpack_from("<I", raw, oh + 112)[0]  # import RVA? 
# Actually for PE32+: standard fields 24, then Windows-specific, DD at +112 from oh start for PE32+
# oh+0 = magic, +112 = import directory RVA for PE32+
imp_rva = struct.unpack_from("<II", raw, oh + 112)[0]
print("import dir rva", hex(imp_rva))

# Simpler: search for string _setjmp3 in file and find IAT
idx = raw.find(b"_setjmp3")
print("_setjmp3 str at", idx, raw[idx:idx+20])
idx2 = raw.find(b"longjmp")
print("longjmp str at", idx2)

# Check shim exports
dll = Path("build_univ14/w2kshim64.dll").read_bytes()
print("dll setjmp3", dll.find(b"_setjmp3"), "longjmp", dll.find(b"longjmp"))
