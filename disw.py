"""Disassemble a region of a PE64 (by RVA) with capstone."""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def rva_to_off(data, rva):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt_sz = struct.unpack_from("<H", data, pe + 20)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    sec = pe + 24 + opt_sz
    for i in range(n):
        o = sec + i * 40
        vs, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        if va <= rva < va + max(vs, rawsz):
            return rawptr + (rva - va)
    return None


def main():
    path = sys.argv[1]
    start = int(sys.argv[2], 16)
    length = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x80
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    off = rva_to_off(data, start)
    if off is None:
        print("rva not mapped")
        return
    code = data[off:off + length]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(code, base + start):
        rva = ins.address - base
        print(f"0x{rva:06X}: {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}")


if __name__ == "__main__":
    main()
