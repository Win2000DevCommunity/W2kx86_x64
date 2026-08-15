import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe = bytearray(pathlib.Path("build_univ228/cmd_diam8.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
blob=pe[rp:rp+rs]
md=Cs(CS_ARCH_X86, CS_MODE_64)

print("=== 1e64a continuation (after first cb) ===")
for insn in md.disasm(bytes(blob[0x1e64a-va:0x1e64a-va+0x150]), ib+0x1e64a):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x1e750: break

# x86 FD5D more + find diamonds with char 0x2f
x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e2 = struct.unpack_from("<I", x86, 0x3C)[0]
ns2 = struct.unpack_from("<H", x86, e2+6)[0]
so2 = struct.unpack_from("<H", x86, e2+20)[0]
sec2 = e2+24+so2
ib2 = struct.unpack_from("<I", x86, e2+24+28)[0]
for i in range(ns2):
    o = sec2+i*40
    if x86[o:o+5]==b".text":
        vs2,va2,rs2,rp2=struct.unpack_from("<IIII", x86, o+8); break
xb=x86[rp2:rp2+rs2]
md32=Cs(CS_ARCH_X86, CS_MODE_32)

# find push imm; push imm; push 0x2f/'/'; push table; call
print("\n=== x86 diamonds char 0x2f ===")
i=0
while i < len(xb)-25:
    if xb[i]==0x68 and xb[i+5]==0x68:
        # check for push 0x2f
        j=i+10
        ch=None
        if xb[j]==0x6a and xb[j+1]==0x2f:
            ch=0x2f; j+=2
        elif xb[j]==0x68 and struct.unpack_from('<I',xb,j+1)[0]==0x2f:
            ch=0x2f; j+=5
        if ch and xb[j]==0x68 and xb[j+5]==0xe8:
            p0=struct.unpack_from('<I',xb,i+1)[0]
            p1=struct.unpack_from('<I',xb,i+6)[0]
            tab=struct.unpack_from('<I',xb,j+1)[0]
            print(f"  site {va2+i:x}: next={p0:x} self={p1:x} tab={tab:x}")
            # disasm the two callbacks
            for name,va_cb in [('next',p0),('self',p1)]:
                rva=va_cb-ib2 if va_cb>ib2 else va_cb-0 # image base
                # try as absolute VA
                cb_rva = (p0 if name=='next' else p1) - (ib2 if ib2 else 0x4ad00000)
                # Win2000 cmd base often 0x4ad00000
                base=0x4ad00000
                cb_rva=(p0 if name=='next' else p1)-base
                if 0 < cb_rva-va2 < len(xb):
                    print(f"  --- {name} @ {cb_rva:x} ---")
                    for insn in md32.disasm(xb[cb_rva-va2:cb_rva-va2+40], cb_rva):
                        print(f"    {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
                        if insn.address>cb_rva+30: break
    i+=1
