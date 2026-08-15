from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe=bytearray(pathlib.Path("build_univ230/cmd_both.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
# find fn start
start=None
for off in range(0x262a8-va, max(0,0x262a8-va-0x200), -1):
    if code[off:off+4]==bytes.fromhex('554889e5'):
        start=off; break
print("start", hex(ib+va+start) if start else None)
if start:
    for i, insn in enumerate(md.disasm(code[start:start+0x150], ib+va+start)):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if i>70: break
# resolve IAT 85570 - read name from idata
# PE import: walk import dir
opt=e+24
# data dirs at opt+112 for PE32+, import is index 1
imp_rva,imp_sz=struct.unpack_from("<II",pe,opt+112+8)
print("import dir", hex(imp_rva), hex(imp_sz))
# find which thunk points to... actually IAT values at runtime. In file, IAT may have RVAs to names.
for i in range(ns):
    o=sec+i*40
    if pe[o:o+6]==b".idata":
        iva,irs,irp=struct.unpack_from("<IIII",pe,o+8)[0],struct.unpack_from("<IIII",pe,o+8)[1],struct.unpack_from("<IIII",pe,o+8)[2]
        # slot 0x85570
        off=irp+(0x85570-iva)
        print("iat file qword", hex(struct.unpack_from("<Q",pe,off)[0]))
