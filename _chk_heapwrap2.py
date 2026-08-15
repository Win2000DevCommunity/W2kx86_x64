from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe=bytearray(pathlib.Path("build_univ230/cmd_fix2.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
print("==== 19e30-19e90 alloc return ====")
for insn in md.disasm(code[0x19e30-va:0x19e30-va+0x70], ib+0x19e30):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
print("\n==== 19ffd realloc call cont ====")
for insn in md.disasm(code[0x19ffd-va:0x19ffd-va+0x50], ib+0x19ffd):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# IAT names
def iat_name(slot):
    pe=pathlib.Path("build_univ230/cmd_fix2.exe").read_bytes()
    e=struct.unpack_from("<I",pe,0x3C)[0]; opt=e+24
    imp_rva=struct.unpack_from("<I",pe,opt+112+8)[0]
    def rva_to_off(rva):
        ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
        for i in range(ns):
            o=sec+i*40
            vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
            if va<=rva<va+max(vs,rs): return rp+(rva-va)
        return None
    off=rva_to_off(imp_rva)
    while True:
        oft,td,fwd,name,ft=struct.unpack_from("<IIIII",pe,off)
        if oft==0 and name==0: break
        dll=pe[rva_to_off(name):].split(b"\0")[0]
        iat,idx=ft,0
        while True:
            io=rva_to_off(iat+idx*8)
            thunk=struct.unpack_from("<Q",pe,io)[0]
            if thunk==0: break
            if iat+idx*8==slot:
                if thunk>>(63): return f"ord{thunk&0xffff}@{dll}"
                return pe[rva_to_off(thunk)+2:].split(b"\0")[0].decode()+f"@{dll.decode()}"
            idx+=1
        off+=20
    return "?"
for s in [0x843e0,0x843d8,0x84578]:
    print(hex(s), iat_name(s))
