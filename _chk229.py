import struct, pathlib
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pathlib.Path("build_univ229/cmd_pure.exe").read_bytes()
trva, data, ib = read_text_section(pe)
md = Cs(CS_ARCH_X86, CS_MODE_64)
for s in [0x3624d, 0x1d4f4, 0x1d534, 0x1d574]:
    off = s - trva
    if data[off:off+2] == b"\x48\xb9" and data[off+17:off+19] == b"\x49\xb8":
        r8 = struct.unpack_from("<Q", data, off+19)[0]
        r9 = struct.unpack_from("<Q", data, off+29)[0]
        ch = struct.unpack_from("<I", data, off+13)[0]
        def tip(va):
            if not (ib <= va < ib + 0x50000):
                return "OUT"
            o = (va - ib) - trva
            return data[o:o+2].hex()
        print(f"{s:#x} ch={ch:#x} r8={(r8-ib)&0xffffffff:#x}[{tip(r8)}] r9={(r9-ib)&0xffffffff:#x}[{tip(r9)}]")

idx = 0
while True:
    k = data.find(bytes.fromhex("81fb00000100"), idx)
    if k < 0:
        break
    print(f"cmp ebx,10000 at {(trva+k):#x}")
    for insn in md.disasm(data[k:k+40], trva+k):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address > trva + k + 30:
            break
    idx = k + 1
