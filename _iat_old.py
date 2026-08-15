import os, sys, struct, pathlib
os.environ["PURE"]="1"
sys.path.insert(0,".")
from x86x64.pe.pe32 import PE32Image
from x86x64.dispatch.transform import transform_imports

src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
pe=PE32Image(src)
imports=transform_imports(pe.parse_imports())
# find wcsncpy old iat
for imp in imports:
  for i,fn in enumerate(imp["functions"]):
    if fn=="wcsncpy" or (isinstance(fn,tuple) and "wcsncpy" in str(fn)):
      print("found", imp["dll"], fn, "idx", i)
# print iat rvas from pe
print("old base", hex(pe.image_base))
# parse IAT addresses from pe file for 0x4ad01204
import pefile
p=pefile.PE(data=src)
for e in p.DIRECTORY_ENTRY_IMPORT:
  for imp in e.imports:
    if imp.name==b"wcsncpy":
      print("x86 wcsncpy", hex(imp.address), "rva", hex(imp.address-p.OPTIONAL_HEADER.ImageBase))