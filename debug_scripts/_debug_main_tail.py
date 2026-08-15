"""Debug _fix_cmd_main_tail_scope_hole failure reasons."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Patch translator to hook main_tail
import x86_x64 as m

orig = m.PETranslator._fix_cmd_main_tail_scope_hole

def dbg(self, out, rva_map=None):
    if not self.text_rva or rva_map is None:
        print("FAIL: no text_rva or rva_map")
        return 0
    hole_rva = 0x3FDA0
    partial_rva = 0x3FD62
    hole_off = hole_rva - self.text_rva
    print(f"text_rva=0x{self.text_rva:X} hole_off=0x{hole_off:X} len={len(out)}")
    if hole_off < 0 or hole_off + 16 > len(out):
        print("FAIL: hole bounds")
        return 0
    sent = out[hole_off:hole_off + 4]
    print(f"hole sentinel: {sent.hex()}")
    if sent != b'\xff\xff\xff\xff':
        print("FAIL: not scope hole")
        return 0
    sec = self.pe.section_for_rva(0xDBB0)
    if not sec:
        print("FAIL: no sec")
        return 0
    text_data = self.pe.get_section_data(sec)
    for x86_tail in (0xDBEE, 0xDCEE, 0xDBB0 + (hole_rva - partial_rva)):
        x86_end = 0xDE99
        t_off = x86_tail - sec['vaddr']
        e_off = x86_end - sec['vaddr']
        blob = text_data[t_off:e_off]
        chunk_out, chunk_map = self._translate_function(
            x86_tail, blob, False, 0, chunk_base=hole_off,
            section_rva=self.text_rva, global_rva_map=rva_map,
            deferred_branches=[])
        print(f"x86_tail=0x{x86_tail:X} x86_len=0x{len(blob):X} out_len=0x{len(chunk_out) if chunk_out else 0:X}")
    scope_len = 64
    sled = self._find_nop_run(out, scope_len)
    print(f"sled={None if sled is None else hex(sled)} hole_off={hex(hole_off)}")
    return orig(self, out, rva_map)

m.PETranslator._fix_cmd_main_tail_scope_hole = dbg

if __name__ == "__main__":
    src = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
    out = str(Path(__file__).resolve().parent.parent / "win2000_x64" / "cmd_shim_dbg.exe")
    argv = [src, out, "--ntdll-ref", r"C:\Windows\System32\ntdll.dll", "--static-only", "--win10-test-shim"]
    sys.argv = ["x86_x64.py"] + argv
    m.main()
