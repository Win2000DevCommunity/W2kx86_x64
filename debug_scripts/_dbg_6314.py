import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

X86 = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
SHIM = r"..\win2000_x64\cmd_shim.exe"


def load_text(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    n = struct.unpack_from("<H", d, pe + 6)[0]
    sec = pe + 24 + opt
    for i in range(n):
        o = sec + i * 40
        if d[o : o + 8].split(b"\0")[0] == b".text":
            rp = struct.unpack_from("<I", d, o + 20)[0]
            rsz = struct.unpack_from("<I", d, o + 16)[0]
            tva = struct.unpack_from("<I", d, o + 12)[0]
            return d, d[rp : rp + rsz], tva
    raise SystemExit("no .text")


def section_strings(path, rvas):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    n = struct.unpack_from("<H", d, pe + 6)[0]
    sec = pe + 24 + opt
    for rva in rvas:
        for i in range(n):
            o = sec + i * 40
            name = d[o : o + 8].split(b"\0")[0].decode(errors="ignore")
            va, vs, rs, rp = struct.unpack_from("<III", d, o + 8)
            if va <= rva < va + max(vs, rs):
                s = d[rp + (rva - va) : rp + (rva - va) + 80].split(b"\0")[0]
                print(f"rva 0x{rva:X} in {name}: {s!r}")


def main():
    xd, xtd, xtva = load_text(X86)
    sd, std, stva = load_text(SHIM)

    print("x86 734A:", xd[xtd.find(bytes.fromhex("8b45848945ac")) + (0x734A - 0x7344) :][:15].hex())
    off = 0x734A - xtva
    print("x86 734A insn bytes:", xtd[off : off + 10].hex())

    off = 0x89F6 - stva
    print("shim 89F6 bytes:", std[off : off + 40].hex())
    rel = struct.unpack_from("<i", std, off + 0x21)[0]
    print("shim call at 8A17 ->", hex(0x8A17 + 5 + rel))

    section_strings(X86, [0x16E8, 0x161C, 0x16C8, 0x1810, 0x18F7])

    md32 = Cs(CS_ARCH_X86, CS_MODE_32)
    print("\n=== x86 6314 ===")
    for ins in md32.disasm(xtd[0x6314 - xtva : 0x6314 - xtva + 0x100], 0x6314):
        print(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
        if ins.address > 0x6390:
            break

    print("\nshim calls from 8800-8C00:")
    for i in range(len(std) - 5):
        if std[i] != 0xE8:
            continue
        rva = stva + i
        if not (0x8800 <= rva <= 0x8C00):
            continue
        rel = struct.unpack_from("<i", std, i + 1)[0]
        tgt = rva + 5 + rel
        print(f"  0x{rva:X} -> 0x{tgt:X}")

    # find translated 6314: x86 calls 6578 from 6325
    rel = struct.unpack_from("<i", xtd, 0x6325 - xtva + 1)[0]
    print("\nx86 6314 inner call ->", hex(0x6325 + 5 + rel))

    pat = struct.pack("<Q", 0x800023B00 & 0xFFFFFFFFFFFFFFFF)
    j = std.find(struct.pack("<Q", 0x800023B00))
    print("shim 23b00 imm hits:", hex(stva + j) if j >= 0 else "none")

    md64 = Cs(CS_ARCH_X86, CS_MODE_64)
    for q in [0x800018F7, 0x800016E8]:
        idx = 0
        while True:
            j = std.find(struct.pack("<Q", q), idx)
            if j < 0:
                break
            rva = stva + j
            print(f"\nshim movabs {hex(q)} at 0x{rva:X}")
            ctx = std[max(0, j - 16) : j + 32]
            for ins in md64.disasm(ctx, max(stva, stva + j - 16)):
                if ins.address > rva + 20:
                    break
                mark = ">>>" if ins.address == rva else "   "
                print(f"{mark} 0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
            idx = j + 1


if __name__ == "__main__":
    main()
