import pathlib, struct, subprocess
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

raw = pathlib.Path("build_univ31/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, e + 6)[0]
opt = struct.unpack_from("<H", raw, e + 20)[0]
s0 = e + 24 + opt
for i in range(n):
    o = s0 + i * 40
    name = raw[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", raw, o + 8)
    if name.startswith(b".text"):
        break
text = raw[rp : rp + rsz]
text_rva = va
rmap = {}
for ln in pathlib.Path("build_univ31/rva.txt").read_text().splitlines():
    a = ln.split()
    rmap[int(a[0], 16)] = int(a[1], 16)
print("222e", hex(rmap.get(0x222E, 0)))
md = Cs(CS_ARCH_X86, CS_MODE_64)
off = rmap[0x222E] - text_rva
for insn in md.disasm(text[off - 20 : off + 40], rmap[0x222E] - 20):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

exe = str(pathlib.Path("build_univ31/cmd_pure.exe").resolve())
p = subprocess.run(
    [exe, "/c", "echo", "w2ktest"],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    timeout=20,
)
print("rc", p.returncode)
print("stdout", p.stdout)
print("stderr", p.stderr[:300])
