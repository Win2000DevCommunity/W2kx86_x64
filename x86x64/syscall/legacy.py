"""Syscall table lookup and NTDLL stub extraction as the legacy translator uses
them.  New code should prefer :mod:`x86x64.syscall.table`.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403
from x86x64.pe.image32 import PE32Image


def set_syscall_target(target: str) -> None:
    """Select which x64 syscall numbering scheme translated stubs use."""
    global _SYSCALL_TARGET
    if target not in ('win2000', 'win10'):
        raise ValueError(f"syscall target must be 'win2000' or 'win10', got {target!r}")
    _SYSCALL_TARGET = target
def get_syscall_target() -> str:
    return _SYSCALL_TARGET
def resolve_syscall_nr(name: str, w2k_nr: int) -> int:
    """
    Resolve the x64 syscall number placed in RAX by translated stubs.

    win2000: use the Win2000 index from ntdll (our x64 kernel SSDT uses the
             same semantic numbering — NT 5.0 never shipped x64, we define it).
    win10:   map by Nt* name to published Win10 x64 direct-syscall numbers.
    """
    if _SYSCALL_TARGET == 'win2000':
        return w2k_nr
    return resolve_win10_syscall(name, w2k_nr)
def apply_win10_syscall_map(by_name: Dict[str, int]) -> int:
    """Apply Win10 x64 syscall numbers by Nt* name to global lookup tables."""
    updated = 0
    for w2k, w10_old, nargs, name in WIN2000_SYSCALL_TABLE:
        w10 = w10_old
        if name in by_name:
            w10 = by_name[name]
        elif name.startswith('Zw'):
            nt_name = 'Nt' + name[2:]
            if nt_name in by_name:
                w10 = by_name[nt_name]
        if name in by_name or (name.startswith('Zw') and ('Nt' + name[2:]) in by_name):
            if w10 != w10_old:
                updated += 1
        _W2K_NR_TO_INFO[w2k] = (w10, nargs, name)
        _W2K_NAME_TO_NR[name] = w2k
        _WIN10_NAME_TO_NR[name] = w10
    return updated
def count_mapped_syscalls() -> Tuple[int, int, List[str]]:
    """Return (mapped, total, unmapped_names) from live lookup table."""
    seen: Set[int] = set()
    unmapped: List[str] = []
    for w2k, (_w10, _, name) in _W2K_NR_TO_INFO.items():
        if w2k in seen or name.startswith("Zw"):
            continue
        seen.add(w2k)
        if name not in _WIN10_SYSCALL_NAMES:
            unmapped.append(name)
    return len(seen) - len(unmapped), len(seen), unmapped
def count_syscall_coverage() -> Tuple[int, int, List[str]]:
    """Return (mapped, total, unmapped) for the active syscall target."""
    if _SYSCALL_TARGET == 'win2000':
        seen: Set[int] = set()
        for w2k, (_, _, name) in _W2K_NR_TO_INFO.items():
            if name.startswith('Zw'):
                continue
            seen.add(w2k)
        total = len(seen)
        return total, total, []
    return count_mapped_syscalls()
def export_syscall_table_json(path: str, pe: Optional['PE32Image'] = None) -> int:
    """
    Write the active Win2000 syscall table to JSON.

    Each entry: {name, win2000_nr, x64_nr, n_args, mechanism}
    x64_nr follows --syscall-target (win2000 index or Win10 mapping).
    """
    stubs: List[StubInfo]
    if pe is not None:
        stubs = extract_stubs_from_ntdll(pe)
    else:
        stubs = []
        for w2k, (_w10, nargs, name) in sorted(_W2K_NR_TO_INFO.items()):
            if name.startswith('Zw'):
                continue
            stubs.append(StubInfo(0, name, w2k, _w10, nargs, nargs * 4, 'INT2E', b''))

    rows = []
    for s in stubs:
        rows.append({
            'name': s.name,
            'win2000_nr': s.win2000_nr,
            'x64_nr': resolve_syscall_nr(s.name, s.win2000_nr),
            'n_args': s.n_args,
            'mechanism': s.mechanism,
            'target': _SYSCALL_TARGET,
        })
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(rows, f, indent=2)
    return len(rows)
def auto_load_win10_syscall_table() -> int:
    """Load bundled or local win10_x64_syscalls.json if present."""
    global _WIN10_SYSCALL_NAMES
    candidates = [
        os.path.join(_REPO_ROOT, "win10_x64_syscalls.json"),
        os.path.join(os.getcwd(), "win10_x64_syscalls.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            by_name = {k: int(v) for k, v in data.items()}
            _WIN10_SYSCALL_NAMES = set(by_name.keys())
            n = apply_win10_syscall_map(by_name)
            print(f"[+] Applied {n} Win10 x64 syscall mappings from {path}")
            return n
    return 0
def resolve_win10_syscall(name: str, w2k_nr: int) -> int:
    """Resolve Win10 x64 syscall number for a stub."""
    if name in _WIN10_NAME_TO_NR:
        return _WIN10_NAME_TO_NR[name]
    if name.startswith('Zw'):
        return _WIN10_NAME_TO_NR.get('Nt' + name[2:], 0)
    info = _W2K_NR_TO_INFO.get(w2k_nr)
    return info[0] if info else 0
def load_syscall_table_from_ntdll(path: str) -> int:
    """Extract syscall numbers from a real ntdll.dll and refresh global lookup maps."""
    with open(path, 'rb') as f:
        pe = PE32Image(f.read())
    stubs = extract_stubs_from_ntdll(pe)
    updated = 0
    for s in stubs:
        if s.name.startswith('Zw'):
            continue
        w10 = resolve_win10_syscall(s.name, s.win2000_nr)
        _W2K_NR_TO_INFO[s.win2000_nr] = (w10, s.n_args, s.name)
        _W2K_NAME_TO_NR[s.name] = s.win2000_nr
        _WIN10_NAME_TO_NR[s.name] = w10
        updated += 1
    return updated
class StubInfo:
    """Information about a decoded NTDLL syscall stub."""
    __slots__ = ('rva', 'name', 'win2000_nr', 'win10_nr',
                 'n_args', 'ret_pop', 'mechanism', 'raw')

    def __init__(self, rva, name, w2k_nr, w10_nr, n_args, ret_pop, mech, raw):
        self.rva       = rva
        self.name      = name
        self.win2000_nr= w2k_nr
        self.win10_nr  = w10_nr
        self.n_args    = n_args
        self.ret_pop   = ret_pop
        self.mechanism = mech   # 'INT2E' or 'SYSENTER'
        self.raw       = raw    # original bytes

    def __repr__(self):
        return (f"StubInfo({self.name}, w2k=0x{self.win2000_nr:04X}, "
                f"w10=0x{self.win10_nr:04X}, args={self.n_args})")
def extract_stubs_from_ntdll(pe: PE32Image) -> List[StubInfo]:
    """
    Walk every export, identify the Win2000 NTDLL stub pattern, and extract
    the real syscall numbers + argument counts.

    Win2000 SP4 stub layout (16 bytes per stub, aligned):
      B8 [4-byte syscall_nr]      MOV EAX, <nr>
      8D 54 24 04                  LEA EDX, [ESP+4]
      CD 2E                        INT 0x2E
      C2 [2-byte ret_bytes] / C3   RET <n> / RET

    Some stubs on CPUs supporting SYSENTER use:
      B8 [4-byte syscall_nr]      MOV EAX, <nr>
      8D 54 24 04                  LEA EDX, [ESP+4]  (or 8B D4: MOV EDX, ESP)
      0F 34                        SYSENTER
      ...
    """
    stubs: List[StubInfo] = []
    exports = pe.parse_exports()

    for exp in exports:
        name = exp['name']
        if not (name.startswith('Nt') or name.startswith('Zw')):
            continue

        func_rva = exp['rva']
        stub_off = pe.rva_to_offset(func_rva)
        if stub_off is None:
            continue
        stub = pe.raw[stub_off : stub_off + 16]
        if len(stub) < 12:
            continue

        # Must start with MOV EAX, imm32  (B8 xx xx xx xx)
        if stub[0] != 0xB8:
            continue
        w2k_nr = struct.unpack_from('<I', stub, 1)[0]

        # Check for LEA EDX,[ESP+4]  or  MOV EDX,ESP
        lea_edx_esp4 = (stub[5:9] == b'\x8d\x54\x24\x04')
        mov_edx_esp  = (stub[5:7] == b'\x8b\xd4')

        if not (lea_edx_esp4 or mov_edx_esp):
            continue

        body_off = 9 if lea_edx_esp4 else 7
        body = stub[body_off:]

        if body[:2] == b'\xcd\x2e':    # INT 2Eh
            mech = 'INT2E'
            ret_off = body_off + 2
        elif body[:2] == b'\x0f\x34':  # SYSENTER
            mech = 'SYSENTER'
            ret_off = body_off + 2
        else:
            continue

        ret_bytes = stub[ret_off:]
        if ret_bytes[0] == 0xC2:       # RET N
            ret_pop = struct.unpack_from('<H', ret_bytes, 1)[0]
        elif ret_bytes[0] == 0xC3:     # RET
            ret_pop = 0
        else:
            ret_pop = 0

        n_args = ret_pop // 4

        # Look up x64 syscall number for the active target
        x64_nr = resolve_syscall_nr(name, w2k_nr)

        stubs.append(StubInfo(
            rva       = func_rva,
            name      = name,
            w2k_nr    = w2k_nr,
            w10_nr    = x64_nr,
            n_args    = n_args,
            ret_pop   = ret_pop,
            mech      = mech,
            raw       = bytes(stub),
        ))

    stubs.sort(key=lambda s: s.win2000_nr)
    return stubs
def dump_syscall_table(pe: PE32Image) -> None:
    """Print the syscall table extracted from a real ntdll.dll."""
    stubs = extract_stubs_from_ntdll(pe)
    target = get_syscall_target()
    x64_col = 'Win2000 x64' if target == 'win2000' else 'Win10 x64'
    print(f"\n{'─'*78}")
    print(f"  Windows 2000 SP4 NTDLL Syscall Table ({len(stubs)} entries)")
    print(f"  Target: {target}  (x64 stubs use {x64_col} numbering)")
    print(f"{'─'*78}")
    print(f"  {'Win2000':>8}  {x64_col:>12}  {'Args':>5}  {'Mech':>8}  Function")
    print(f"  {'─'*8}  {'─'*12}  {'─'*5}  {'─'*8}  {'─'*40}")
    for s in stubs:
        x64 = f"0x{s.win10_nr:04X}" if s.win10_nr or target == 'win2000' else "NO MAP"
        print(f"  0x{s.win2000_nr:04X}      {x64:>12}  {s.n_args:>5}  {s.mechanism:>8}  {s.name}")
    print(f"{'─'*78}\n")
