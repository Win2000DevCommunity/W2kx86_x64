"""Map module file offsets/RVAs to nearest preceding export name."""
import struct
import sys


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


def exports(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    exp_rva, _ = struct.unpack_from("<II", data, dd)
    eoff = rva_to_off(data, exp_rva)
    nfun, nname = struct.unpack_from("<II", data, eoff + 20)
    addr_funcs = struct.unpack_from("<I", data, eoff + 28)[0]
    addr_names = struct.unpack_from("<I", data, eoff + 32)[0]
    addr_ords = struct.unpack_from("<I", data, eoff + 36)[0]
    fo = rva_to_off(data, addr_funcs)
    no = rva_to_off(data, addr_names)
    oo = rva_to_off(data, addr_ords)
    out = []
    for i in range(nname):
        nrva = struct.unpack_from("<I", data, no + i * 4)[0]
        ordi = struct.unpack_from("<H", data, oo + i * 2)[0]
        frva = struct.unpack_from("<I", data, fo + ordi * 4)[0]
        s = rva_to_off(data, nrva)
        nm = b""
        while data[s] != 0:
            nm += bytes([data[s]])
            s += 1
        out.append((frva, nm.decode("ascii", "replace")))
    out.sort()
    return out


def main():
    path = sys.argv[1]
    targets = [int(x, 16) for x in sys.argv[2:]]
    exp = exports(path)
    for t in targets:
        best = None
        for frva, nm in exp:
            if frva <= t:
                best = (frva, nm)
            else:
                break
        if best:
            print(f"0x{t:X}  ->  {best[1]} + 0x{t-best[0]:X}  (export rva 0x{best[0]:X})")
        else:
            print(f"0x{t:X}  ->  (no export below)")


if __name__ == "__main__":
    main()
