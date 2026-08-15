"""Patch longjmp in existing w2kshim64.dll (same-sized REX.R fix)."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import w2kseh64

fresh = w2kseh64.build_longjmp()
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("fixed longjmp:")
for insn in md.disasm(fresh, 0):
    print(f"  {insn.address:#04x}  {insn.bytes.hex():16s} {insn.mnemonic} {insn.op_str}")

for dll_path in [Path("build_univ13/w2kshim64.dll"), Path("build_univ12/w2kshim64.dll")]:
    if not dll_path.exists():
        continue
    data = bytearray(dll_path.read_bytes())
    # Old broken sequence: mov rdx,[rcx+0x28] with REX.W only
    old = bytes.fromhex("488b5128")  # mov rdx, [rcx+0x28]
    new = bytes.fromhex("4c8b5128")  # mov r10, [rcx+0x28]
    # Prefer replacing the full longjmp body if present
    # Find by unique prologue of longjmp
    pro = w2kseh64._mov_reg_qword_rcx_disp('rbp', 0)  # may differ
    # Search for old rip load inside dll
    count = 0
    idx = 0
    while True:
        i = data.find(old, idx)
        if i < 0:
            break
        # Only patch if followed by mov rax,[rcx+0x30] (JB_SEH) = 488b4130
        if data[i+4:i+8] == bytes.fromhex("488b4130"):
            data[i:i+4] = new
            count += 1
            print(f"{dll_path}: patched rip-load at {i:#x}")
        idx = i + 1
    if count:
        dll_path.write_bytes(data)
        print(f"  wrote {count} patch(es)")
    else:
        # Maybe already has fresh body from rebuild - search fresh
        fi = data.find(fresh[:24])
        print(f"{dll_path}: fresh prefix at {fi}, old-pattern patches={count}")
        if fi >= 0 and data[fi:fi+len(fresh)] != fresh:
            if len(data) >= fi + len(fresh):
                # sizes should match
                old_len = len(fresh)
                data[fi:fi+old_len] = fresh
                dll_path.write_bytes(data)
                print("  replaced full longjmp body")
