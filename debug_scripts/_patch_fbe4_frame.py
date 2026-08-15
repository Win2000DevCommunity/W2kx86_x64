import struct
from pathlib import Path
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

raw = bytearray(Path("build_univ117/cmd_heal3.exe").read_bytes())
e = struct.unpack_from("<I", raw, 0x3c)[0]
nsec = struct.unpack_from("<H", raw, e + 6)[0]
opt = struct.unpack_from("<H", raw, e + 20)[0]
soff = e + 24 + opt
for i in range(nsec):
    o = soff + i * 40
    name = bytes(raw[o:o + 8]).split(b"\0")[0]
    va, vsz, rs, rp = struct.unpack_from("<IIII", raw, o + 8)
    if name == b".text":
        text_fo, text_rs, trva = rp, rs, va
        break
blob = bytearray(raw[text_fo:text_fo + text_rs])

# 1) mov rax,[r13+0x48] -> mov eax,[rsp+0x20]  (4 bytes)
old = bytes.fromhex("498b4548")
new = bytes.fromhex("8b442420")
# only in fbe4 region
off = blob.find(old, 0x1e200 - trva, 0x1e290 - trva)
print("r13 fix at", hex(off + trva) if off >= 0 else None)
if off >= 0:
    blob[off:off + 4] = new

# 2) epilogue xor rax,rax; pop*4; ret -> trampoline with add rsp,0x10
epi = bytes.fromhex("4831c05f5e5d5bc3")
off = blob.find(epi, 0x1e280 - trva, 0x1e2a0 - trva)
print("epi at", hex(off + trva) if off >= 0 else None)
if off >= 0:
    stub = bytearray()
    stub += b"\x31\xc0"          # xor eax,eax
    stub += b"\x5f\x5e\x5d\x5b"  # pop rdi..rbx
    stub += b"\x48\x83\xc4\x10"  # add rsp,0x10
    stub += b"\xc3"              # ret
    # find pad at end of text
    need = len(stub)
    pad = None
    run = 0
    for p in range(len(blob) - 1, max(0, len(blob) - 0x8000), -1):
        if blob[p] in (0x00, 0x90, 0xCC):
            run += 1
            if run >= need:
                pad = p - run + 1
                break
        else:
            run = 0
    if pad is None:
        pad = len(blob)
        blob.extend(b"\x00" * need)
    blob[pad:pad + need] = stub
    # jmp to stub (5 bytes) + nops to fill 8
    rel = pad - (off + 5)
    blob[off:off + 8] = b"\xe9" + struct.pack("<i", rel) + b"\x90\x90\x90"

# 3) in fbe4 body, scale inc dword [rsp+0x10]/[rsp+0x14] if present
# ff 44 24 10 -> ff 44 24 20 ; ff 44 24 14 -> ff 44 24 28
for a, b in ((0x10, 0x20), (0x14, 0x28)):
    pat = bytes([0xFF, 0x44, 0x24, a])
    rep = bytes([0xFF, 0x44, 0x24, b])
    start = 0x1df1c - trva
    end = 0x1e294 - trva
    i = start
    n = 0
    while i < end:
        j = blob.find(pat, i, end)
        if j < 0:
            break
        blob[j:j + 4] = rep
        n += 1
        i = j + 4
    print(f"inc [rsp+{a:#x}] -> +{b:#x}: {n}")

# 4) cmp dword [rsp+0x14], eax : 83 7c 24 14 -> 83 7c 24 28
pat = bytes.fromhex("837c2414")
rep = bytes.fromhex("837c2428")
i = 0x1df1c - trva
end = 0x1e294 - trva
n = 0
while i < end:
    j = blob.find(pat, i, end)
    if j < 0:
        break
    blob[j:j + 4] = rep
    n += 1
    i = j + 4
print("cmp [rsp+0x14]:", n)

raw[text_fo:text_fo + len(blob)] = blob[:text_rs] if len(blob) <= text_rs else blob
if len(blob) > text_rs:
    # text grew - can't easily expand PE; ensure stub fit in section
    print("WARNING text grew", len(blob) - text_rs)
    raw[text_fo:text_fo + text_rs] = blob[:text_rs]
else:
    raw[text_fo:text_fo + text_rs] = blob + bytes(text_rs - len(blob))

# Actually if we grew blob beyond text_rs, stub may be truncated. Check pad.
print("blob len", len(blob), "text_rs", text_rs)

Path("build_univ117/cmd_heal4.exe").write_bytes(raw[:text_fo] + blob[:text_rs].ljust(text_rs, b"\x00") + raw[text_fo+text_rs:] if False else bytes(raw))
# rewrite cleanly
raw2 = bytearray(Path("build_univ117/cmd_heal3.exe").read_bytes())
# re-do with guarantee stub inside section
blob = bytearray(raw2[text_fo:text_fo + text_rs])
off = blob.find(bytes.fromhex("498b4548"), 0x1e200 - trva, 0x1e290 - trva)
if off >= 0:
    blob[off:off + 4] = bytes.fromhex("8b442420")
    print("re-fixed r13")
for a, b in ((0x10, 0x20), (0x14, 0x28)):
    pat = bytes([0xFF, 0x44, 0x24, a]); rep = bytes([0xFF, 0x44, 0x24, b])
    i = 0x1df1c - trva; end = 0x1e294 - trva
    while i < end:
        j = blob.find(pat, i, end)
        if j < 0: break
        blob[j:j+4] = rep; i = j+4
pat = bytes.fromhex("837c2414"); rep = bytes.fromhex("837c2428")
i = 0x1df1c - trva; end = 0x1e294 - trva
while i < end:
    j = blob.find(pat, i, end)
    if j < 0: break
    blob[j:j+4] = rep; i = j+4

off = blob.find(bytes.fromhex("4831c05f5e5d5bc3"), 0x1e280 - trva, 0x1e2a0 - trva)
stub = bytes.fromhex("31c05f5e5d5b4883c410c3")
# find zero run inside section
pad = None; run = 0; run_start = 0
for p in range(len(blob) - 1, 0, -1):
    if blob[p] in (0, 0x90, 0xCC):
        if run == 0: run_start = p
        run += 1
        if run >= len(stub) and run_start < len(blob):
            pad = run_start - run + 1
            if pad > 0x1000:  # keep in high text
                break
    else:
        run = 0
print("pad", hex(pad + trva) if pad is not None else None, "off", hex(off+trva) if off>=0 else None)
if off >= 0 and pad is not None:
    blob[pad:pad + len(stub)] = stub
    rel = pad - (off + 5)
    blob[off:off + 8] = b"\xe9" + struct.pack("<i", rel) + b"\x90\x90\x90"

raw2[text_fo:text_fo + text_rs] = blob
Path("build_univ117/cmd_heal4.exe").write_bytes(raw2)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== fail path")
for insn in md.disasm(blob[0x1e240 - trva:0x1e2a0 - trva], 0x80000000 + 0x1e240):
    print(f"{insn.address:x}: {insn.mnemonic} {insn.op_str}")
