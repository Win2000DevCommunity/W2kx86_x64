import pathlib, struct, subprocess
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

raw = pathlib.Path("build_univ32/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, e + 6)[0]
opt = struct.unpack_from("<H", raw, e + 20)[0]
s0 = e + 24 + opt
for i in range(n):
    o = s0 + i * 40
    name = raw[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", raw, o + 8)
    if name.startswith(b".text"):
        text = raw[rp : rp + rsz]
        text_rva = va
        break
rmap = {}
for ln in pathlib.Path("build_univ32/rva.txt").read_text().splitlines():
    a = ln.split()
    rmap[int(a[0], 16)] = int(a[1], 16)
print("e846", hex(rmap.get(0xE846, 0)))
md = Cs(CS_ARCH_X86, CS_MODE_64)
off = rmap[0xE846]
print("==== e846 body ====")
for insn in md.disasm(text[off - text_rva : off - text_rva + 80], off):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == "ret" and insn.address > off + 20:
        break

exe = str(pathlib.Path("build_univ32/cmd_pure.exe").resolve())
p = subprocess.run(
    [exe, "/c", "echo", "w2ktest"],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    timeout=20,
)
print("rc", p.returncode, hex(p.returncode & 0xFFFFFFFF))
print("stdout", p.stdout)
print("stderr", p.stderr[:200])
