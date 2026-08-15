import sys, pefile, bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

build = sys.argv[1] if len(sys.argv) > 1 else "build_out41"
tgt = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x1263A

fwd = {}
for l in open(build + r"\rva.txt"):
    a, b = l.split()
    fwd[int(a, 16)] = int(b, 16)
rev = {v: k for k, v in fwd.items()}
keys = sorted(rev)
i = bisect.bisect_right(keys, tgt) - 1
tr = keys[i]
x86 = rev[tr]
print("translated 0x%X <= nearest 0x%X -> x86 0x%X (+%d)" % (tgt, tr, x86, tgt - tr))

pe = pefile.PE(build + r"\cmd_pure.exe")
data = pe.get_memory_mapped_image()
md64 = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- translated x64 @ 0x%X ---" % tr)
for ins in md64.disasm(bytes(data[tr:tr + 0x60]), tr):
    print("  %06x  %s %s" % (ins.address, ins.mnemonic, ins.op_str))

xpath = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
xpe = pefile.PE(xpath)
xdata = xpe.get_memory_mapped_image()
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
start = x86 - 0x10
print("--- original x86 @ 0x%X ---" % x86)
for ins in md32.disasm(bytes(xdata[start:start + 0x50]), start):
    mark = " <==" if ins.address == x86 else ""
    print("  %06x  %s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
