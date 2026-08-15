import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

for name in ["build_univ257/cmd_pure.exe", "build_univ258/cmd_probe_wfs.exe"]:
    pe = pefile.PE(name)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(f"\n=== {name} @ 458A0 ===")
    b = pe.get_data(0x458A0, 0x30)
    print("raw", b.hex())
    for i in md.disasm(b, 0x800458A0):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# x86 - find cmp ax,28h / cmp ax,40h pattern near get-line
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
text = x86.get_data(0x1000, 0x1A000)
# 66 3D 28 00 = cmp ax, 0x28
for off in range(len(text)-10):
    if text[off:off+4] == bytes.fromhex("663d2800") or text[off:off+3]==bytes.fromhex("6683f828"):
        # check nearby for 40
        window = text[off:off+20]
        if b"\x40" in window[4:12]:
            print(f"\nx86 at {off+0x1000:#x}")
            for i in md32.disasm(text[off:off+25], off+0x1000):
                print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
