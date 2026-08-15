import struct, pathlib
# replicate _iat_slot_ok / resolve offline using univ55 idata plan
pe=pathlib.Path("build_univ55/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]; ib=struct.unpack_from("<Q",pe,e+24+24)[0]
import pefile
p=pefile.PE(data=pe)
# idata rva
idata=None
for s in p.sections:
  if s.Name.startswith(b".idata"):
    idata=s.VirtualAddress; print("idata", hex(idata)); break
# Build map like _plan_import_iat_map: name->rva
# Just check slot
slot=None
for exp in p.DIRECTORY_ENTRY_IMPORT:
  for imp in exp.imports:
    if imp.name==b"wcsncpy":
      slot=imp.address
print("slot", hex(slot), "rva", hex(slot-ib), "ok", (slot-ib)>=0x20000)
# At 14d70 in univ55 what is there?
nsec=struct.unpack_from("<H",pe,e+6)[0]; sz=struct.unpack_from("<H",pe,e+20)[0]; so=e+24+sz
for i in range(nsec):
  o=so+i*40; name=pe[o:o+8].split(b"\0",1)[0]
  vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
  if name.startswith(b".text"):
    out=pe[raw:raw+rsz]; tva=va; break
off=0x14d70-tva
print("14d70", out[off:off+32].hex())
off=0x14d68-tva
print("14d68", out[off:off+40].hex())