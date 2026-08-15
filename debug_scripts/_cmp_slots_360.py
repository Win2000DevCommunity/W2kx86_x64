"""Compare shim IAT slot layout + refs between two builds."""
import struct
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SLOT_START = 0x800A4E48
SLOT_END = 0x800A4ED0

def load(build):
    path = f'{build}/cmd_pure.exe'
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    idata = next(s for s in pe.sections if b'.idata' in s.Name)
    text = next(s for s in pe.sections if b'.text' in s.Name)
    return pe, base, idata, text

def dump_ilt(pe, idata):
    # find import descriptor pointing at shim
    imp_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    off = imp_dir.VirtualAddress - idata.VirtualAddress + idata.PointerToRawData
    out = []
    while True:
        orig_thunk, ts, fc, name_rva, first_thunk = struct.unpack_from('<IIIII', pe.__data__, off)
        if orig_thunk == 0 and name_rva == 0:
            break
        name_off = name_rva - idata.VirtualAddress + idata.PointerToRawData
        end = pe.__data__.find(b'\x00', name_off)
        dll = pe.__data__[name_off:end].decode(errors='replace')
        ilt = orig_thunk or first_thunk
        out.append((dll, ilt, first_thunk))
        off += 20
    return out

def slot_map(pe, idata, ilt):
    slots = {}
    for i in range(40):
        fo = ilt - idata.VirtualAddress + idata.PointerToRawData + i * 8
        if fo + 8 > len(pe.__data__):
            break
        val = struct.unpack_from('<Q', pe.__data__, fo)[0]
        if val == 0:
            break
        rva = ilt + i * 8
        if val & (1 << 63):
            slots[rva] = f'ord{val & 0xFFFF}'
        else:
            hint_off = (val & 0x7FFFFFFF) - idata.VirtualAddress + idata.PointerToRawData
            end = pe.__data__.find(b'\x00', hint_off + 2)
            slots[rva] = pe.__data__[hint_off + 2:end].decode(errors='replace')
    return slots

def scan_refs(pe, base, text, slots):
    data = text.get_data()
    va = base + text.VirtualAddress
    refs = {}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    # movabs r64, imm64
    i = 0
    while i < len(data) - 10:
        if data[i] in (0x48, 0x49, 0x4C, 0x4D) and 0xB8 <= data[i+1] <= 0xBF:
            imm = struct.unpack_from('<Q', data, i + 2)[0]
            if SLOT_START <= imm < SLOT_END:
                refs.setdefault(imm, []).append(('movabs', va + i))
            i += 10
            continue
        i += 1
    # push imm32
    i = 0
    while i < len(data) - 5:
        if data[i] == 0x68:
            imm32 = struct.unpack_from('<I', data, i + 1)[0]
            if SLOT_START <= imm32 < SLOT_END:
                refs.setdefault(imm32, []).append(('push32', va + i))
            i += 5
            continue
        i += 1
    # FF 25 / FF 15
    i = 0
    while i < len(data) - 6:
        if data[i] == 0xFF and data[i+1] in (0x25, 0x15):
            rel = struct.unpack_from('<i', data, i + 2)[0]
            tgt = va + i + 6 + rel
            if SLOT_START <= tgt < SLOT_END:
                refs.setdefault(tgt, []).append(('ff', va + i))
            i += 6
            continue
        i += 1
    return refs

def disasm_around(pe, base, text, va, n=24):
    data = text.get_data()
    off = va - (base + text.VirtualAddress)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(data[off:off+n], va))

for build in sys.argv[1:]:
    pe, base, idata, text = load(build)
    print(f'===== {build} (base 0x{base:X}) =====')
    for dll, ilt, first_thunk in dump_ilt(pe, idata):
        if 'shim' in dll.lower() or 'w2k' in dll.lower():
            slots = slot_map(pe, idata, ilt)
            print(f'  {dll} ILT@0x{ilt:X} IAT@0x{first_thunk:X}')
            for rva, name in slots.items():
                print(f'    slot 0x{rva:X}: {name}')
            break
    refs = scan_refs(pe, base, text, slots)
    for rva in sorted(refs):
        name = slots.get(rva, '?')
        kinds = {}
        for k, va in refs[rva]:
            kinds[k] = kinds.get(k, 0) + 1
        print(f'  refs to 0x{base + rva:X} ({name}): {len(refs[rva])} {kinds}')
    # show context of s9 refs in the last build only
    if '360' in build:
        for rva in sorted(refs):
            if rva == 0xA4E90 or rva == 0xA4E98 or rva == 0xA4EA0:
                for k, va in refs[rva]:
                    print(f'  -- ctx @0x{va:X} ({k}) -> 0x{base+rva:X}:')
                    for insn in disasm_around(pe, base, text, va):
                        print(f'     0x{insn.address:X}: {insn.mnemonic} {insn.op_str}')
