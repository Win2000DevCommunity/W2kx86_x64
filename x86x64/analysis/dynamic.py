"""Unicorn-backed dynamic scanning, used to recover branch targets that static
analysis cannot prove.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403
from x86x64.analysis.discover import discover_function_rvas

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # annotation-only, and importing it eagerly would cycle
    from x86x64.pe.image32 import PE32Image


@dataclass
class DynamicScanResult:
    """Results from Unicorn dynamic analysis."""
    pointer_values: Set[int] = field(default_factory=set)   # values pointing into image
    pointer_writes: Dict[int, int] = field(default_factory=dict)  # site_va -> written value
    visited_blocks: Set[int] = field(default_factory=set)   # RVAs of executed basic blocks
    call_targets: Set[int] = field(default_factory=set)     # RVAs reached by CALL/JMP
    branch_targets: Set[int] = field(default_factory=set)   # all taken branch destinations
    entries_emulated: int = 0
    blocks_executed: int = 0
class DynamicScanner:
    """
    Unicorn-based dynamic analysis of a Win2000 PE32 image.

    Mandatory pass: emulates from the entry point, every export, and every
    detected NTDLL syscall stub to harvest runtime pointer values that static
    analysis cannot see (switch tables, computed addresses, vtables, etc.).
    """

    MAX_BLOCKS_PER_ENTRY = 8_000
    MAX_TOTAL_BLOCKS     = 80_000
    MAX_ENTRIES          = 300
    TIMEOUT_US           = 15_000_000   # 15 seconds per entry
    PAGE_SIZE            = 0x1000
    STACK_SIZE           = 0x80000      # 512 KiB stack

    def __init__(self, pe: PE32Image, entry_rva: Optional[int] = None,
                 stub_rvas: Optional[Set[int]] = None):
        if not HAS_UNICORN:
            raise RuntimeError("Unicorn is required for dynamic analysis: pip install unicorn")
        self.pe          = pe
        self.entry_rva   = entry_rva or pe.entry_rva
        self.stub_rvas   = stub_rvas or set()
        self.result      = DynamicScanResult()
        self._total_blocks = 0

    def _align_up(self, n: int, a: int) -> int:
        return (n + a - 1) & ~(a - 1)

    def _collect_entry_points(self) -> List[int]:
        eps: Set[int] = set()
        if self.entry_rva:
            eps.add(self.entry_rva)
        eps.update(self.stub_rvas)
        for exp in self.pe.parse_exports():
            eps.add(exp['rva'])
        for sec_meta, sec_data in self.pe.get_executable_sections():
            for rva in discover_function_rvas(self.pe, sec_data, sec_meta['vaddr']):
                eps.add(rva)
                if len(eps) >= self.MAX_ENTRIES:
                    break
            if len(eps) >= self.MAX_ENTRIES:
                break
        return sorted(eps)[:self.MAX_ENTRIES]

    def _setup_emu(self) -> Tuple:
        pe   = self.pe
        base = pe.image_base
        img_va_end = base + pe.image_size
        map_size = self._align_up(pe.image_size, self.PAGE_SIZE)
        stack_base = self._align_up(img_va_end + 0x10000, self.PAGE_SIZE)

        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(base, map_size, UC_PROT_ALL)

        for sec in pe.sections:
            if sec['raw_ptr'] and sec['raw_sz']:
                data = pe.get_section_data(sec)
                va   = base + sec['vaddr']
                write_sz = min(len(data), map_size - sec['vaddr'])
                if write_sz > 0:
                    mu.mem_write(va, data[:write_sz])

        mu.mem_map(stack_base, self.STACK_SIZE, UC_PROT_ALL)
        return mu, base, img_va_end, stack_base

    def _emulate_from(self, mu, entry_va: int, base: int, img_va_end: int,
                      stack_base: int) -> None:
        esp_init = stack_base + self.STACK_SIZE - 0x400
        mu.reg_write(UC_X86_REG_ESP, esp_init)
        mu.reg_write(UC_X86_REG_EBP, esp_init)
        mu.mem_write(esp_init, struct.pack('<I', img_va_end + 0x200))
        # Seed argument registers for thiscall/fastcall probes
        mu.reg_write(UC_X86_REG_ECX, base + 0x1000)
        mu.reg_write(UC_X86_REG_EDX, base + 0x2000)

        lo, hi = base, img_va_end
        blocks_this_entry = 0

        def _hook_write(uc, access, addr, size, value, user_data):
            v32 = value & 0xFFFFFFFF
            if lo <= v32 < hi:
                self.result.pointer_values.add(v32)
            if size >= 4 and lo <= addr < hi:
                self.result.pointer_writes[addr] = v32

        def _hook_block(uc, address, size, user_data):
            nonlocal blocks_this_entry
            blocks_this_entry += 1
            self._total_blocks += 1
            self.result.blocks_executed = self._total_blocks
            if lo <= address < hi:
                self.result.visited_blocks.add(address - base)
            if (blocks_this_entry >= self.MAX_BLOCKS_PER_ENTRY or
                    self._total_blocks >= self.MAX_TOTAL_BLOCKS):
                uc.emu_stop()

        def _hook_code(uc, address, size, user_data):
            """Simulate syscalls, record branch targets, skip bad calls."""
            try:
                code = uc.mem_read(address, min(size, 16))
            except Exception:
                return
            if lo <= address < hi:
                self.result.visited_blocks.add(address - base)
            # INT 0x2E / SYSENTER — pretend success
            if len(code) >= 2 and code[0] == 0xCD and code[1] == 0x2E:
                uc.reg_write(UC_X86_REG_EAX, 0)
                eip = uc.reg_read(UC_X86_REG_EIP)
                uc.reg_write(UC_X86_REG_EIP, eip + 2)
                return
            if len(code) >= 2 and code[0] == 0x0F and code[1] == 0x34:
                uc.reg_write(UC_X86_REG_EAX, 0)
                eip = uc.reg_read(UC_X86_REG_EIP)
                uc.reg_write(UC_X86_REG_EIP, eip + 2)
                return
            # Record E8/E9 rel32 branch targets for function discovery
            if code[0] == 0xE8 and len(code) >= 5:
                rel = struct.unpack_from('<i', code, 1)[0]
                tgt = (address + 5 + rel) & 0xFFFFFFFF
                if lo <= tgt < hi:
                    self.result.call_targets.add(tgt - base)
                    self.result.branch_targets.add(tgt - base)
            elif code[0] == 0xE9 and len(code) >= 5:
                rel = struct.unpack_from('<i', code, 1)[0]
                tgt = (address + 5 + rel) & 0xFFFFFFFF
                if lo <= tgt < hi:
                    self.result.call_targets.add(tgt - base)
                    self.result.branch_targets.add(tgt - base)
            elif len(code) >= 2 and 0x70 <= code[0] <= 0x7F:
                rel = struct.unpack_from('b', code, 1)[0]
                tgt = (address + 2 + rel) & 0xFFFFFFFF
                if lo <= tgt < hi:
                    self.result.branch_targets.add(tgt - base)
            elif (len(code) >= 6 and code[0] == 0x0F
                    and 0x80 <= code[1] <= 0x8F):
                rel = struct.unpack_from('<i', code, 2)[0]
                tgt = (address + 6 + rel) & 0xFFFFFFFF
                if lo <= tgt < hi:
                    self.result.branch_targets.add(tgt - base)

        def _hook_invalid(uc, access, address, size, value, user_data):
            return False

        mu.hook_add(UC_HOOK_MEM_WRITE, _hook_write)
        mu.hook_add(UC_HOOK_BLOCK, _hook_block)
        mu.hook_add(UC_HOOK_CODE, _hook_code)
        mu.hook_add(UC_HOOK_MEM_INVALID, _hook_invalid)

        try:
            mu.emu_start(entry_va, img_va_end, timeout=self.TIMEOUT_US)
        except Exception:
            pass

    def scan(self) -> DynamicScanResult:
        mu, base, img_va_end, stack_base = self._setup_emu()
        for ep_rva in self._collect_entry_points():
            if self._total_blocks >= self.MAX_TOTAL_BLOCKS:
                break
            self.result.entries_emulated += 1
            self._emulate_from(mu, base + ep_rva, base, img_va_end, stack_base)
        return self.result
