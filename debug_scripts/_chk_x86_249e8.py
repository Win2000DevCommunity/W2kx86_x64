from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct, pathlib
from x86x64.pe import PE32Image
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# find 66 8B 3D xx xx xx xx where imm points near .data+0x628
# Win2k cmd image base 0x4ad00000, .data often 0x4ad1xxxx
for off in range(len(td)-8):
    if td[off:off+2]==b'\x66\x8b' and td[off+2]==0x3d:
        imm=struct.unpack_from("<I",td,off+3)[0]
        if (imm & 0xFFFF) == 0x8628 or ((imm - pe32.image_base) & 0xFFFFF) == 0x18628:
            rva=sec32.vaddr+off
            print(f"hit x86 rva={rva:#x} va={pe32.image_base+rva:#x} imm={imm:#x}")
            # walk back to push ebp
            start=off
            for b in range(off, max(0,off-0x80), -1):
                if td[b]==0x55 and td[b+1]==0x8b and td[b+2]==0xec:
                    start=b; break
            for insn in md32.disasm(td[start:start+0x50], pe32.image_base+sec32.vaddr+start):
                print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
            # find epilogue
            print("  --- epi search ---")
            for insn in md32.disasm(td[start:start+0x400], pe32.image_base+sec32.vaddr+start):
                if insn.mnemonic=='ret':
                    # print last 8 insns - restart
                    pass
            # dump near leave/ret
            for i in range(start, min(len(td)-1, start+0x500)):
                if td[i]==0xc3 and td[i-1]==0xc9:  # leave; ret
                    for insn in md32.disasm(td[i-12:i+1], pe32.image_base+sec32.vaddr+i-12):
                        print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                    break
            break
