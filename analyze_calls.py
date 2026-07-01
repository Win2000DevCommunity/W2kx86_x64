"""Find broken rel32 CALL/JMP in translated PE64 cmd (likely 0xC0000005 cause)."""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

CMD64 = r"C:\Users\Win2000\Desktop\Nouveau dossier (9)\win2000_x64\cmd_shim.exe"
CMD32 = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"


def load_text(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt_off = pe + 24
    opt_sz = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<Q", data, opt_off + 24)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    sec_off = pe + 24 + opt_sz
    for i in range(n):
        o = sec_off + i * 40
        if data[o : o + 5] != b".text":
            continue
        vs, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        return data[rawptr : rawptr + rawsz], va, base
    raise SystemExit("no .text")


def scan_rel32(text, text_rva, base, label):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    zero = bad = cross_gap = 0
    samples = []
    insns = list(md.disasm(text, base + text_rva))
    insn_starts = {i.address for i in insns}

    for insn in insns:
        if insn.mnemonic not in ("call", "jmp") or not insn.operands:
            continue
        op = insn.operands[0]
        if op.type != 1:  # IMM
            continue
        tgt = op.imm
        rel = struct.unpack_from("<i", text, insn.address - base - text_rva + 1)[0] if insn.bytes[0] in (0xE8, 0xE9) else None
        if insn.bytes[0] == 0xE8 and rel == 0:
            zero += 1
            if len(samples) < 8:
                samples.append((label, "CALL rel32=0", hex(insn.address), hex(tgt)))
        tgt_off = tgt - base - text_rva
        if tgt_off < 0 or tgt_off >= len(text):
            bad += 1
            if len(samples) < 12:
                samples.append((label, "CALL out of .text", hex(insn.address), hex(tgt)))
        elif text[tgt_off] == 0xCC:
            cross_gap += 1
            if len(samples) < 12:
                samples.append((label, "CALL into INT3 gap", hex(insn.address), hex(tgt)))
        elif tgt not in insn_starts:
            # target not an instruction boundary
            if len(samples) < 16:
                samples.append((label, "CALL mid-instruction?", hex(insn.address), hex(tgt)))

    print(f"\n{label}  .text={len(text):,}  insns={len(insns):,}")
    print(f"  CALL/JMP rel32=0 (unfixed):     {zero}")
    print(f"  CALL/JMP out of section:        {bad}")
    print(f"  CALL/JMP into INT3/CC padding:  {cross_gap}")
    for s in samples:
        print(f"    {s}")


def main():
    for path, label in [(CMD32, "x86 cmd"), (CMD64, "x64 cmd_shim")]:
        if not __import__("os").path.isfile(path):
            print("missing", path)
            continue
        text, rva, base = load_text(path)
        if label.startswith("x86"):
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            zero = 0
            for insn in md.disasm(text, base + rva):
                if insn.mnemonic == "call" and insn.bytes[:1] == b"\xE8":
                    rel = struct.unpack_from("<i", insn.bytes, 1)[0]
                    if rel == 0:
                        zero += 1
            print(f"\nx86 cmd: CALL rel32=0 in source: {zero}")
        else:
            scan_rel32(text, rva, base, label)


if __name__ == "__main__":
    main()
