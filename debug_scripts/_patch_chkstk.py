"""Patch build_out120 to fix _chkstk frame alignment."""
import shutil

shutil.copy('build_out120/cmd_pure.exe', 'build_out120/cmd_pure_patched.exe')

# .text section at raw offset 0x400
# _chkstk call at blob offset 0x10DAC -> file offset 0x111AC
# imm32 at blob offset 0x10DA8 -> file offset 0x111A8
# Current value: 0x101C -> patch to 0x1020

with open('build_out120/cmd_pure_patched.exe', 'rb+') as f:
    f.seek(0x111A8)
    old = f.read(4)
    ov = int.from_bytes(old, 'little')
    print(f"Old bytes at 0x111A8: {old.hex()} = {ov:#x} (mod16={ov % 16})")
    new = (0x1020).to_bytes(4, 'little')
    f.seek(0x111A8)
    f.write(new)
    print(f"Wrote: {new.hex()} = 0x1020 (mod16=0)")

print("Done!")
