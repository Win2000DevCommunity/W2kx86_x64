#!/usr/bin/env python3
"""
Win2000 x64 SEH / setjmp runtime (XP x64–compatible user-mode layer).

Provides VC6-compatible _setjmp3 / longjmp / _except_handler3 for translated
PE64 binaries, plus a vectored exception handler (installed from w2kshim64
DllMain) that dispatches x86-style GS:[0] SEH frames on native x64 Windows.
"""

from __future__ import annotations
import struct
from typing import Dict, List, Optional, Tuple

# x86 MSVC jmp_buf layout (_setjmp3) — QWORD slots on x64.
# Keep within the classic 0x40-byte VC6 jmp_buf — do NOT extend in-buffer
# (cmd's ``_JumpBuffer`` at .data+… is only that large).
JB_RBP = 0x00
JB_RBX = 0x08
JB_RDI = 0x10
JB_RSI = 0x18
JB_RSP = 0x20
JB_RIP = 0x28
JB_SEH = 0x30
JB_TRYLEVEL = 0x38

# Translated x64 SEH registration frame (8-byte fields).
SEH_FRAME_NEXT = 0x00
SEH_FRAME_HANDLER = 0x08
SEH_FRAME_SCOPE = 0x10
SEH_FRAME_TRYLEVEL = 0x18

# AMD64 CONTEXT (partial) — Win10 x64.
CTX_RBP = 0xA0
CTX_RSP = 0x98
CTX_RIP = 0xF8
EXC_ADDRESS = 0x10

ExceptionContinueExecution = 0
ExceptionContinueSearch = 1
EXCEPTION_EXECUTE_HANDLER = 1
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0


def _u64(*parts: int) -> bytes:
    return b''.join(struct.pack('<B', p & 0xFF) for p in parts)


def _mov_qword_rcx_disp(reg: str, disp: int) -> bytes:
    """mov qword ptr [rcx + disp], reg64 — REX.R for r8–r15."""
    reg_id, rex_r = {
        'rax': (0, 0), 'rcx': (1, 0), 'rdx': (2, 0), 'rbx': (3, 0),
        'rsp': (4, 0), 'rbp': (5, 0), 'rsi': (6, 0), 'rdi': (7, 0),
        'r8': (0, 1), 'r9': (1, 1), 'r10': (2, 1), 'r11': (3, 1),
        'r12': (4, 1), 'r13': (5, 1), 'r14': (6, 1), 'r15': (7, 1),
    }[reg]
    rex = 0x48 | (rex_r << 2)
    if disp == 0:
        modrm = 0x01 | (reg_id << 3)
        return _u64(rex, 0x89, modrm)
    if -0x80 <= disp <= 0x7F:
        modrm = 0x41 | (reg_id << 3)
        return _u64(rex, 0x89, modrm, disp & 0xFF)
    modrm = 0x81 | (reg_id << 3)
    return _u64(rex, 0x89, modrm) + struct.pack('<i', disp)


def _mov_reg_qword_rcx_disp(reg: str, disp: int) -> bytes:
    """mov reg64, qword ptr [rcx + disp] — REX.R for r8–r15."""
    reg_id, rex_r = {
        'rax': (0, 0), 'rcx': (1, 0), 'rdx': (2, 0), 'rbx': (3, 0),
        'rsp': (4, 0), 'rbp': (5, 0), 'rsi': (6, 0), 'rdi': (7, 0),
        'r8': (0, 1), 'r9': (1, 1), 'r10': (2, 1), 'r11': (3, 1),
        'r12': (4, 1), 'r13': (5, 1), 'r14': (6, 1), 'r15': (7, 1),
    }[reg]
    rex = 0x48 | (rex_r << 2)
    if disp == 0:
        modrm = 0x01 | (reg_id << 3)
        return _u64(rex, 0x8B, modrm)
    if -0x80 <= disp <= 0x7F:
        modrm = 0x41 | (reg_id << 3)
        return _u64(rex, 0x8B, modrm, disp & 0xFF)
    modrm = 0x81 | (reg_id << 3)
    return _u64(rex, 0x8B, modrm) + struct.pack('<i', disp)


def build_setjmp3(*, with_nv_save: bool = False) -> bytes:
    """Build ``_setjmp3``.

    When *with_nv_save* is True, also spill call-align nonvolatiles.  ``r13``
    (align-stub frame pointer) is stored in the jmp_buf at ``JB_TRYLEVEL``
    (qword into the unused tail of the 0x40-byte VC6 buf) so concurrent
    setjmps cannot clobber each other's align frames via a global slot —
    that global-r13 race caused cmd interactive stack growth (0xC0/loop).
    ``r12/r14/r15`` still use a shared .data slot (lea patched by the builder).
    """
    code = bytearray()
    code += _mov_qword_rcx_disp('rbp', JB_RBP)
    code += _mov_qword_rcx_disp('rbx', JB_RBX)
    code += _mov_qword_rcx_disp('rdi', JB_RDI)
    code += _mov_qword_rcx_disp('rsi', JB_RSI)
    # Save RSP as it will be *after* returning from setjmp (caller view).
    # Storing raw RSP (which still holds the return address) makes longjmp's
    # ``push rip; ret`` leave RSP 8 bytes low — dangling into the old slot
    # (cmd echo path: longjmp lands executing stack @ saved ``[rsp]`` junk).
    code += _u64(0x48, 0x8D, 0x44, 0x24, 0x08)  # lea rax, [rsp+8]
    code += _mov_qword_rcx_disp('rax', JB_RSP)
    code += _u64(0x48, 0x8B, 0x04, 0x24)        # mov rax, [rsp]  (return RIP)
    code += _mov_qword_rcx_disp('rax', JB_RIP)
    code += _u64(0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00)
    code += _mov_qword_rcx_disp('rax', JB_SEH)
    if with_nv_save:
        # r13 → jmp_buf+0x38 (replaces unused TRYLEVEL dword; needs qword).
        code += _u64(0x4C, 0x89, 0x69, JB_TRYLEVEL)  # mov [rcx+0x38], r13
        # r12/r14/r15 → shared .data (lea patched by builder)
        code += _u64(0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00)
        code += _u64(0x4C, 0x89, 0x60, 0x00)  # mov [rax+0], r12
        code += _u64(0x4C, 0x89, 0x70, 0x08)  # mov [rax+8], r14
        code += _u64(0x4C, 0x89, 0x78, 0x10)  # mov [rax+16], r15
    else:
        code += _u64(0xC7, 0x41, JB_TRYLEVEL, 0x00, 0x00, 0x00, 0x00)
    code += _u64(0x31, 0xC0, 0xC3)
    return bytes(code)


def build_longjmp(*, with_nv_save: bool = False) -> bytes:
    """Build ``longjmp``.

    Spill the retval with ``push rdx`` on the *caller's* stack and restore
    ``RSP`` from the jmp_buf only at the end.  ``r13`` is restored from
    ``[jmp_buf+0x38]`` (per-buffer) so a global NV slot race cannot leave
    the caller's align-stub ``mov rsp,r13`` with a stale frame pointer.
    """
    code = bytearray()
    code += _u64(0x52)  # push rdx  (retval; lives on longjmp-caller stack)
    code += _mov_reg_qword_rcx_disp('rbp', JB_RBP)
    code += _mov_reg_qword_rcx_disp('rbx', JB_RBX)
    code += _mov_reg_qword_rcx_disp('rdi', JB_RDI)
    code += _mov_reg_qword_rcx_disp('rsi', JB_RSI)
    if with_nv_save:
        code += _u64(0x4C, 0x8B, 0x69, JB_TRYLEVEL)  # mov r13, [rcx+0x38]
        code += _u64(0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00)  # lea rax,[rip+0]
        code += _u64(0x4C, 0x8B, 0x60, 0x00)  # mov r12, [rax+0]
        code += _u64(0x4C, 0x8B, 0x70, 0x08)  # mov r14, [rax+8]
        code += _u64(0x4C, 0x8B, 0x78, 0x10)  # mov r15, [rax+16]
    code += _mov_reg_qword_rcx_disp('r10', JB_RIP)
    code += _mov_reg_qword_rcx_disp('rax', JB_SEH)
    code += _u64(0x65, 0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00)
    # Uninitialized jmp_buf has RIP=0; jumping there is execute@0.  Trap instead.
    code += _u64(0x4D, 0x85, 0xD2)  # test r10, r10
    jnz_off = len(code)
    code += _u64(0x75, 0x00)        # jnz .Lrip_ok
    code += _u64(0xCC)              # int3
    rip_ok = len(code)
    code[jnz_off + 1] = rip_ok - (jnz_off + 2)
    # MSVC: longjmp(buf, 0) must return 1 from setjmp.
    code += _u64(0x58)              # pop rax  (retval)
    code += _u64(0x85, 0xC0)        # test eax, eax
    jnz_off = len(code)
    code += _u64(0x75, 0x00)
    code += _u64(0xB8, 0x01, 0x00, 0x00, 0x00)  # mov eax, 1
    skip = len(code)
    code[jnz_off + 1] = skip - (jnz_off + 2)
    # Sign-extend retval into RAX — callers cmp against -1 as 32/64-bit
    # (cmd interactive ``cmp edi, -1`` / ``cmp esi, 1`` after longjmp(-1)).
    code += _u64(0x48, 0x63, 0xC0)  # movsxd rax, eax
    # Switch stack last, then jump — never run TEB/retval logic on target RSP.
    code += _mov_reg_qword_rcx_disp('rsp', JB_RSP)
    code += _u64(0x41, 0x52, 0xC3)  # push r10; ret
    return bytes(code)


def patch_nv_save_lea(fn_blob: bytearray, fn_file_off: int, nv_rva: int,
                      text_rva: int) -> bool:
    """Patch the first ``lea rax,[rip+disp]`` in a setjmp/longjmp stub."""
    for i in range(min(120, len(fn_blob) - 7)):
        if fn_blob[i:i + 3] == b'\x48\x8d\x05':
            disp = nv_rva - (text_rva + fn_file_off + i + 7)
            struct.pack_into('<i', fn_blob, i + 3, disp)
            return True
    return False


def build_seh_longjmp_unwind() -> bytes:
    code = bytearray()
    code += _mov_reg_qword_rcx_disp('rax', JB_SEH)
    code += _u64(0x65, 0x4C, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00)
    loop = len(code)
    code += _u64(0x49, 0x39, 0xC0)
    je_off = len(code)
    code += _u64(0x74, 0x00)
    code += _u64(0x49, 0x83, 0xF8, 0xFF)
    je2_off = len(code)
    code += _u64(0x74, 0x00)
    code += _u64(0x4D, 0x8B, 0x00)
    code += _u64(0x65, 0x4C, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00)
    jmp_back = len(code)
    code += _u64(0xEB, 0x00)
    code[jmp_back + 1] = (loop - (jmp_back + 2)) & 0xFF
    done = len(code)
    code[je_off + 1] = done - (je_off + 2)
    code[je2_off + 1] = done - (je2_off + 2)
    code += _u64(0xC3)
    return bytes(code)


def _ks_asm(asm: str) -> bytes:
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        enc, _ = ks.asm(asm)
        return _fix_gs_abs_disp(bytes(enc))
    except Exception as exc:
        import sys
        print(f'w2kseh64: keystone asm failed: {exc}', file=sys.stderr)
        return b''


def _fix_gs_abs_disp(code: bytes) -> bytes:
    """Keystone emits gs:[rip+0] for gs:[0]; fix to absolute disp32 form."""
    out = bytearray()
    i = 0
    while i < len(code):
        if (i + 8 <= len(code) and code[i] == 0x65 and code[i + 2] == 0x8B
                and code[i + 4:i + 8] == b'\x00\x00\x00\x00'
                and (code[i + 3] & 0xC7) == 0x05):
            rex = code[i + 1]
            reg = (code[i + 3] >> 3) & 7
            if rex & 4:
                reg += 8
            modrm = 0x04 | (((reg & 7) << 3))
            out.extend([0x65, rex, 0x8B, modrm, 0x25, 0, 0, 0, 0])
            i += 8
            continue
        out.append(code[i])
        i += 1
    return bytes(out)


def build_except_handler3(image_base: int = 0x80000000) -> bytes:
    """
    EXCEPTION_DISPOSITION _except_handler3(rec, frame, ctx, disp)

    Walks the x86-format scope table attached to the translated SEH frame.
    """
    scope_lo = image_base
    scope_hi = image_base + 0x01000000
    asm = rf"""
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        mov r10, rdx
        # Safety: if RDX (frame pointer) is below 0x10000 it is not a valid
        # user-mode pointer; return ExceptionContinueSearch immediately.
        # Can be hit when the translator maps a non-SEH x86 call to this
        # IAT slot due to an IAT-mapping edge case.
        movabs r11, 0x10000
        cmp r10, r11
        jb search_done
        mov rbx, qword ptr [r10 + 0x10]
        test rbx, rbx
        jz search_done
        movabs r11, {scope_lo}
        cmp rbx, r11
        jb search_done
        movabs r11, {scope_hi}
        cmp rbx, r11
        jae search_done
        cmp dword ptr [rbx], -1
        jne search_done
        lea r11, [r10 + 0x20]
        movsxd r12, dword ptr [r11 - 8]
        test r12d, r12d
        jns have_trylevel
        xor r12d, r12d
    have_trylevel:
        mov rsi, qword ptr [rcx + 0x10]
    scope_loop:
        test r12d, r12d
        js search_done
        mov rax, r12
        shl rax, 4
        lea rdi, [rbx + rax + 4]
        mov eax, dword ptr [rdi]
        cmp rsi, rax
        jb next_scope
        mov eax, dword ptr [rdi + 4]
        cmp rsi, rax
        jae next_scope
        mov eax, dword ptr [rdi + 8]
        test eax, eax
        jz execute_handler
        cmp eax, 0x10000
        jb execute_handler
        # DWORD scope slots are zero-extended PE64 VAs (image at 0x80000000+).
        # ``movsxd`` would sign-extend into the non-canonical range and #GP.
        movabs r11, {image_base}
        cmp rax, r11
        jae call_filter
        add rax, r11
    call_filter:
        sub rsp, 0x28
        call rax
        add rsp, 0x28
        # MSVC filter: 1 = EXECUTE_HANDLER, 0 = CONTINUE_SEARCH, -1 = CONTINUE_EXECUTION
        cmp eax, 1
        je execute_handler
        jmp next_scope
    execute_handler:
        lea eax, [r12d - 1]
        mov dword ptr [r10 + 0x18], eax
        mov rax, qword ptr [r10]
        mov qword ptr gs:[0], rax
        mov eax, dword ptr [rdi + 12]
        test eax, eax
        jz use_end_as_handler
        cmp eax, 0x10000
        jb use_end_as_handler
        jmp set_handler_rip
    use_end_as_handler:
        mov eax, dword ptr [rdi + 4]
    set_handler_rip:
        # Zero-extend DWORD VA (see call_filter); never sign-extend.
        movabs r11, {image_base}
        cmp rax, r11
        jae rip_ok
        add rax, r11
    rip_ok:
        mov qword ptr [r8 + 0xF8], rax
        mov r11, qword ptr [r8 + 0xA0]
        mov r11, qword ptr [r11 - 0x18]
        mov qword ptr [r8 + 0x98], r11
        lea r11, [r10 + 0x20]
        mov qword ptr [r8 + 0xA0], r11
        xor eax, eax
        jmp epilog
    next_scope:
        dec r12d
        jmp scope_loop
    search_done:
        mov eax, 1
    epilog:
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return _u64(0xB8, ExceptionContinueSearch, 0x00, 0x00, 0x00, 0xC3)


def build_vectored_seh_handler(handler_rva: int, image_base: int,
                               scope_lo: int = 0x80000000,
                               scope_hi: int = 0x81000000) -> bytes:
    """First-chance vectored handler walking GS:[0] MSVC SEH frames."""
    handler_va = image_base + handler_rva
    asm = rf"""
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        mov rbx, rcx
        mov r15, {handler_va:#x}
        mov r14, qword ptr gs:[0]
        xor r13d, r13d
    chain_loop:
        inc r13d
        cmp r13d, 64
        ja continue_search
        test r14, r14
        jz continue_search
        cmp r14, -1
        je continue_search
        cmp r14, 0x10000
        jb continue_search
        test r14b, 7
        jnz next_frame
        mov rax, qword ptr gs:[0x08]
        cmp r14, rax
        jae next_frame
        mov rax, qword ptr gs:[0x10]
        cmp r14, rax
        jb next_frame
        mov rax, qword ptr [r14 + 0x10]
        test rax, rax
        jz next_frame
        mov r11, {scope_lo:#x}
        cmp rax, r11
        jb next_frame
        mov r11, {scope_hi:#x}
        cmp rax, r11
        jae next_frame
        cmp dword ptr [rax], -1
        jne next_frame
        mov rax, qword ptr [r14 + 0x8]
        test rax, rax
        jz next_frame
        mov r11, {scope_lo:#x}
        cmp rax, r11
        jb check_shim_handler
        mov r11, {scope_hi:#x}
        cmp rax, r11
        jb handler_ok
    check_shim_handler:
        mov r11, {handler_va:#x}
        cmp rax, r11
        jne next_frame
    handler_ok:
        mov rcx, qword ptr [rbx]
        mov rdx, r14
        mov r8, qword ptr [rbx + 8]
        xor r9d, r9d
        sub rsp, 0x20
        call r15
        add rsp, 0x20
        test eax, eax
        jnz check_search
        mov eax, -1
        jmp done
    check_search:
        cmp eax, 1
        je next_frame
        jmp continue_search
    next_frame:
        mov rax, qword ptr [r14]
        cmp rax, r14
        je continue_search
        mov r14, rax
        jmp chain_loop
    continue_search:
        or r10, -1
        mov rax, qword ptr [rbx]
        mov edx, dword ptr [rax]
        mov eax, 0x2C
        syscall
        test eax, eax
        jz done
        xor eax, eax
    done:
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return _u64(0x31, 0xC0, 0xC3)


def build_dllmain_install_vectored(
        vectored_rva: int,
        image_base: int,
        iat_add_vectored_rva: int,
        except_handler3_rva: int,
        iat_seterr_rva: int = 0,
) -> bytes:
    """DllMain: SetErrorMode (no JIT UI) + AddVectoredExceptionHandler on attach."""
    vectored_va = image_base + vectored_rva
    iat_va = image_base + iat_add_vectored_rva
    seterr_iat = image_base + iat_seterr_rva if iat_seterr_rva else 0
    eh3_va = image_base + except_handler3_rva
    seterr_block = ""
    if seterr_iat:
        seterr_block = rf"""
        mov ecx, 0x8003
        sub rsp, 0x28
        mov rax, {seterr_iat}
        call qword ptr [rax]
        add rsp, 0x28
"""
    asm = rf"""
        cmp edx, 1
        jne dm_not_attach
        movzx eax, word ptr [rcx]
        cmp ax, 0x5A4D
        jne dm_not_attach
{seterr_block}        mov ecx, 1
        mov rdx, {vectored_va}
        sub rsp, 0x28
        mov rax, {iat_va}
        call qword ptr [rax]
        add rsp, 0x28
        mov eax, 1
        ret
    dm_not_attach:
        cmp edx, 0
        jne dm_chk_edx2
        mov eax, 1
        ret
    dm_chk_edx2:
        cmp edx, 2
        jne dm_chk_edx3
        mov eax, 1
        ret
    dm_chk_edx3:
        cmp edx, 3
        jne dm_seh_try
        mov eax, 1
        ret
    dm_seh_try:
        test rcx, rcx
        jz dm_kuser_check
        mov eax, dword ptr [rcx]
        cmp eax, 0x80000000
        jb dm_kuser_check
        cmp eax, 0xC0000000
        jae dm_kuser_check
        test rdx, rdx
        jnz dm_call_eh3
        mov rdx, qword ptr gs:[0]
        test rdx, rdx
        jz dm_kuser_check
    dm_call_eh3:
        sub rsp, 0x28
        mov rax, {eh3_va}
        call rax
        add rsp, 0x28
        ret
    dm_kuser_check:
        mov rax, qword ptr [rsp]
        cmp rax, 0x7FFE0000
        jb dm_ret_one
        cmp rax, 0x7FFE1000
        jae dm_ret_one
        mov rdx, qword ptr gs:[0]
        test rdx, rdx
        jz dm_ret_one
        sub rsp, 0x28
        mov rax, {eh3_va}
        call rax
        add rsp, 0x28
        ret
    dm_ret_one:
        mov eax, 1
        ret
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return _u64(0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3)


# Win32 RTL_CRITICAL_SECTION is 0x18; Win64 is 0x28.  Guest .data keeps the
# Win32 object; shims map guest VA → a real host CRITICAL_SECTION in .data.
CS_HOST_SIZE = 0x28
CS_SLOT_SIZE = 0x30          # QWORD guest_va + 0x28 host CS
CS_MAX_SLOTS = 64
CS_MAP_BYTES = CS_SLOT_SIZE * CS_MAX_SLOTS


def build_shim_idata(text_rva: int, idata_rva: int
                     ) -> Tuple[bytes, int, int, int, int, int, int, int, int]:
    """
    Minimal PE64 import directory: KERNEL32 SetErrorMode +
    AddVectoredExceptionHandler + VirtualQuery + GetStdHandle +
    CriticalSection Init/Enter/Leave/Delete (host-sized wrappers).

    Returns (idata_blob, add_vectored_iat_rva, seterr_iat_rva,
             virtualquery_iat_rva, getstdhandle_iat_rva,
             initcs_iat_rva, entercs_iat_rva, leavecs_iat_rva,
             deletecs_iat_rva).
    """
    dll_name = b'KERNEL32.dll\x00'
    fns = [
        (b'SetErrorMode\x00', b'\x00\x00SetErrorMode\x00'),
        (b'AddVectoredExceptionHandler\x00',
         b'\x00\x00AddVectoredExceptionHandler\x00'),
        (b'VirtualQuery\x00', b'\x00\x00VirtualQuery\x00'),
        (b'GetStdHandle\x00', b'\x00\x00GetStdHandle\x00'),
        (b'InitializeCriticalSection\x00',
         b'\x00\x00InitializeCriticalSection\x00'),
        (b'EnterCriticalSection\x00',
         b'\x00\x00EnterCriticalSection\x00'),
        (b'LeaveCriticalSection\x00',
         b'\x00\x00LeaveCriticalSection\x00'),
        (b'DeleteCriticalSection\x00',
         b'\x00\x00DeleteCriticalSection\x00'),
    ]
    desc_size = 40  # one descriptor + null
    ilt_off = desc_size
    iat_off = ilt_off + (len(fns) + 1) * 8
    hint_off = iat_off + (len(fns) + 1) * 8
    cursor = hint_off
    hints: List[bytes] = []
    for _fn, hint in fns:
        hints.append(hint)
        cursor += len(hint)
    dll_off = cursor
    total = dll_off + len(dll_name)

    blob = bytearray(total)
    struct.pack_into('<IIIII', blob, 0,
                     idata_rva + ilt_off, 0, 0,
                     idata_rva + dll_off, idata_rva + iat_off)
    off = hint_off
    for i, (_fn, hint) in enumerate(fns):
        hint_rva = idata_rva + off
        blob[off:off + len(hint)] = hint
        off += len(hint)
        struct.pack_into('<Q', blob, ilt_off + i * 8, hint_rva)
        struct.pack_into('<Q', blob, iat_off + i * 8, hint_rva)
    blob[dll_off:dll_off + len(dll_name)] = dll_name
    return (bytes(blob), idata_rva + iat_off + 8, idata_rva + iat_off,
            idata_rva + iat_off + 16, idata_rva + iat_off + 24,
            idata_rva + iat_off + 32, idata_rva + iat_off + 40,
            idata_rva + iat_off + 48, idata_rva + iat_off + 56)


def build_cs_init_shim(map_va: int, init_iat_va: int,
                       max_slots: int = CS_MAX_SLOTS) -> bytes:
    """Map guest Win32 CS VA → host Win64 CRITICAL_SECTION, then Init.

    rcx = lpCriticalSection (guest .data address, Win32-sized).
    """
    asm = rf"""
        push rbx
        push rsi
        sub rsp, 0x28
        mov rbx, rcx
        mov rsi, {map_va:#x}
        mov ecx, {max_slots}
    cs_init_scan:
        cmp qword ptr [rsi], rbx
        je cs_init_found
        cmp qword ptr [rsi], 0
        je cs_init_empty
        add rsi, {CS_SLOT_SIZE:#x}
        dec ecx
        jnz cs_init_scan
        xor eax, eax
        jmp cs_init_done
    cs_init_empty:
        mov qword ptr [rsi], rbx
    cs_init_found:
        lea rcx, [rsi + 8]
        mov rax, {init_iat_va:#x}
        call qword ptr [rax]
    cs_init_done:
        add rsp, 0x28
        pop rsi
        pop rbx
        ret
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return bytes([0xC3])


def build_cs_enter_shim(map_va: int, enter_iat_va: int,
                        max_slots: int = CS_MAX_SLOTS) -> bytes:
    """Resolve guest CS VA to host CRITICAL_SECTION and Enter."""
    asm = rf"""
        push rsi
        sub rsp, 0x20
        mov rsi, {map_va:#x}
        mov edx, {max_slots}
    cs_enter_scan:
        cmp qword ptr [rsi], rcx
        je cs_enter_found
        add rsi, {CS_SLOT_SIZE:#x}
        dec edx
        jnz cs_enter_scan
        add rsp, 0x20
        pop rsi
        ret
    cs_enter_found:
        lea rcx, [rsi + 8]
        mov rax, {enter_iat_va:#x}
        add rsp, 0x20
        pop rsi
        jmp qword ptr [rax]
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return bytes([0xC3])


def build_cs_leave_shim(map_va: int, leave_iat_va: int,
                        max_slots: int = CS_MAX_SLOTS) -> bytes:
    """Resolve guest CS VA to host CRITICAL_SECTION and Leave."""
    asm = rf"""
        push rsi
        sub rsp, 0x20
        mov rsi, {map_va:#x}
        mov edx, {max_slots}
    cs_leave_scan:
        cmp qword ptr [rsi], rcx
        je cs_leave_found
        add rsi, {CS_SLOT_SIZE:#x}
        dec edx
        jnz cs_leave_scan
        add rsp, 0x20
        pop rsi
        ret
    cs_leave_found:
        lea rcx, [rsi + 8]
        mov rax, {leave_iat_va:#x}
        add rsp, 0x20
        pop rsi
        jmp qword ptr [rax]
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return bytes([0xC3])


def build_cs_delete_shim(map_va: int, delete_iat_va: int,
                         max_slots: int = CS_MAX_SLOTS) -> bytes:
    """Delete host CRITICAL_SECTION and free the guest→host map slot."""
    asm = rf"""
        push rbx
        push rsi
        sub rsp, 0x28
        mov rbx, rcx
        mov rsi, {map_va:#x}
        mov ecx, {max_slots}
    cs_del_scan:
        cmp qword ptr [rsi], rbx
        je cs_del_found
        add rsi, {CS_SLOT_SIZE:#x}
        dec ecx
        jnz cs_del_scan
        xor eax, eax
        jmp cs_del_done
    cs_del_found:
        lea rcx, [rsi + 8]
        mov rax, {delete_iat_va:#x}
        call qword ptr [rax]
        mov qword ptr [rsi], 0
    cs_del_done:
        add rsp, 0x28
        pop rsi
        pop rbx
        ret
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return bytes([0xC3])


def build_get_osfhandle_shim(getstd_iat_va: int) -> bytes:
    """Map CRT fds 0/1/2 to GetStdHandle without touching msvcrt ``__pioinfo``.

    Win2000 apps call ``_get_osfhandle`` after their own CRT startup; on Win10
    that leaves msvcrt's ``__pioinfo`` null, so the real export AVs on
    ``test [rax+rcx+8],1``.  Std handles are enough for console I/O (cmd echo,
    WriteFile-via-fd checks); other fds return ``INVALID_HANDLE_VALUE`` (-1).
    """
    asm = rf"""
        push rbp
        mov rbp, rsp
        sub rsp, 0x20
        movsxd rax, ecx
        cmp eax, 0
        je gosfh_in
        cmp eax, 1
        je gosfh_out
        cmp eax, 2
        je gosfh_err
        mov rax, -1
        jmp gosfh_done
    gosfh_in:
        mov ecx, 0xfffffff6
        jmp gosfh_call
    gosfh_out:
        mov ecx, 0xfffffff5
        jmp gosfh_call
    gosfh_err:
        mov ecx, 0xfffffff4
    gosfh_call:
        mov rax, {getstd_iat_va:#x}
        call qword ptr [rax]
    gosfh_done:
        add rsp, 0x20
        pop rbp
        ret
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    return bytes([0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3])  # mov rax,-1; ret


def build_virtualquery_shim(vq_iat_va: int) -> bytes:
    """x86-ABI VirtualQuery wrapper.

    Win2000 x86 code calls ``VirtualQuery(addr, &mbi, sizeof(MBI))`` with
    ``sizeof(MEMORY_BASIC_INFORMATION) == 0x1C`` and frequently checks that the
    return value equals 0x1C.  On x64 the struct is 0x30 bytes, so a direct call
    returns 0x30 (or 0 for the too-small buffer) and every such check fails.

    This wrapper calls the real kernel32 VirtualQuery with a private 0x30 buffer,
    repacks the result into the caller's 0x1C x86-layout buffer, and returns
    0x1C — restoring Win32 semantics for any translated binary.

        rcx = lpAddress, rdx = lpBuffer (x86, 0x1C), r8 = dwLength (ignored)
    """
    asm = rf"""
        push rbp
        mov rbp, rsp
        push rsi
        push rdi
        sub rsp, 0x50
        mov rdi, rdx
        lea rdx, [rsp + 0x20]
        mov r8d, 0x30
        mov rax, {vq_iat_va:#x}
        call qword ptr [rax]
        test eax, eax
        jz vq_fail
        lea rsi, [rsp + 0x20]
        mov rax, qword ptr [rsi]
        mov dword ptr [rdi], eax
        mov rax, qword ptr [rsi + 8]
        mov dword ptr [rdi + 4], eax
        mov eax, dword ptr [rsi + 0x10]
        mov dword ptr [rdi + 8], eax
        mov rax, qword ptr [rsi + 0x18]
        mov dword ptr [rdi + 0xc], eax
        mov eax, dword ptr [rsi + 0x20]
        mov dword ptr [rdi + 0x10], eax
        mov eax, dword ptr [rsi + 0x24]
        mov dword ptr [rdi + 0x14], eax
        mov eax, dword ptr [rsi + 0x28]
        mov dword ptr [rdi + 0x18], eax
        mov eax, 0x1c
        jmp vq_done
    vq_fail:
        xor eax, eax
    vq_done:
        add rsp, 0x50
        pop rdi
        pop rsi
        pop rbp
        ret
    """
    blob = _ks_asm(asm)
    if blob:
        return blob
    # Degraded fallback: zero the buffer and report the x86 struct size.
    return _u64(0xB8, 0x1C, 0x00, 0x00, 0x00, 0xC3)


def seh_export_stubs() -> Dict[str, bytes]:
    return {
        '_setjmp3': build_setjmp3(),
        'longjmp': build_longjmp(),
        '_seh_longjmp_unwind': build_seh_longjmp_unwind(),
        '_except_handler3': build_except_handler3(),
    }


WOW64_XP64_MODULES = [
    'wow64.dll',
    'wow64cpu.dll',
    'wow64win.dll',
    'ntdll.dll',
    'syswow64/ntdll.dll',
    'syswow64/wow64.dll',
]