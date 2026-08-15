import struct
from pathlib import Path

src = Path("build_envfix2/cmd_pure.exe")
dst = Path("build_envfix3/cmd_pure.exe")
dst.parent.mkdir(exist_ok=True)
blob = bytearray(src.read_bytes())

pe = struct.unpack_from("<I", blob, 0x3C)[0]
img = struct.unpack_from("<Q", blob, pe + 24 + 24)[0]
n = struct.unpack_from("<H", blob, pe + 6)[0]
opt = struct.unpack_from("<H", blob, pe + 20)[0]
sec = pe + 24 + opt

def va_to_fo(va):
    rva = va - img
    for i in range(n):
        off = sec + i * 40
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", blob, off + 8)
        if vaddr <= rva < vaddr + rsize:
            return rptr + (rva - vaddr)
    raise KeyError(hex(va))

# Original 13 bytes from 0x9e7e:
# 56 49 8b 4d 20 41 55 49 89 e5 48 83 ec 20
# push rsi; mov rcx,[r13+0x20]; push r13; mov r13,rsp; sub rsp,0x20
# Keep and rsp separate (still at 0x9e8c)

fo = va_to_fo(0x80009e7e)
orig = blob[fo:fo+13]
print("orig13", orig.hex(), len(orig))
# new 13 bytes:
# 56 48 89 d6 41 55 48 89 f1 49 89 e5 48 83 ec 20
# push rsi; mov rsi,rdx; push r13; mov rcx,rsi; mov r13,rsp; sub rsp,0x20
new = bytes.fromhex("564889d641554889f14989e54883ec20")
print("new13", new.hex(), len(new))
assert len(new) == 13
blob[fo:fo+13] = new

fo2 = va_to_fo(0x80009eae)
orig2 = blob[fo2:fo2+10]
print("setenv", orig2.hex())
assert orig2 == bytes.fromhex("498b4d18498b5520")
# mov rcx, rdi; mov rdx, rsi; nop nop nop nop
blob[fo2:fo2+10] = bytes.fromhex("4889f94889f290909090")

dst.write_bytes(blob)
(dst.parent / "w2kshim64.dll").write_bytes(Path("build_envfix2/w2kshim64.dll").read_bytes())
print("wrote", dst)

# verify disasm
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from tools.audit_calls import read_text_section
trva, data, _ = read_text_section(bytes(blob))
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- patched region ---")
for ins in md.disasm(data[0x9e7e-trva:0x9ee0-trva], 0x9e7e):
    print("%#07x  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
