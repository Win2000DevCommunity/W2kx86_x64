"""Builds w2kshim64.dll, the compatibility DLL that backs Win2000 imports with
modern equivalents.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403


def _shim_asm(asm_text: str) -> bytes:
    """Assemble x64 stub bytes for the shim DLL."""
    if not HAS_KEYSTONE:
        manual = {
            'mov eax, 1; ret': bytes([0xB8, 1, 0, 0, 0, 0xC3]),
            'xor eax, eax; ret': bytes([0x31, 0xC0, 0xC3]),
            'ret': bytes([0xC3]),
        }
        return manual.get(asm_text, b'\xC3')
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    enc, _ = ks.asm(asm_text)
    return bytes(enc)
def build_w2kshim64_dll() -> bytes:
    """
    Build a minimal PE64 DLL exporting Win2000-only imports for Win10 x64.

    Provides InterlockedExchange and legacy MSVCRT VC6 entry points that were
    dropped from x64 System32.
    """
    try:
        from w2kseh64 import (
            seh_export_stubs,
            build_setjmp3,
            build_longjmp,
            patch_nv_save_lea,
            build_vectored_seh_handler,
            build_dllmain_install_vectored,
            build_shim_idata,
            build_virtualquery_shim,
            build_get_osfhandle_shim,
            build_cs_init_shim,
            build_cs_enter_shim,
            build_cs_leave_shim,
            build_cs_delete_shim,
            CS_MAP_BYTES,
        )
        _seh_stubs = seh_export_stubs()
    except ImportError:
        _seh_stubs = {}
        build_setjmp3 = None  # type: ignore
        build_longjmp = None  # type: ignore
        patch_nv_save_lea = None  # type: ignore
        build_vectored_seh_handler = None  # type: ignore
        build_dllmain_install_vectored = None  # type: ignore
        build_shim_idata = None  # type: ignore
        build_virtualquery_shim = None  # type: ignore
        build_get_osfhandle_shim = None  # type: ignore
        build_cs_init_shim = None  # type: ignore
        build_cs_enter_shim = None  # type: ignore
        build_cs_leave_shim = None  # type: ignore
        build_cs_delete_shim = None  # type: ignore
        CS_MAP_BYTES = 0  # type: ignore

    FILE_ALIGN = 0x200
    SECT_ALIGN = 0x1000

    def align(n: int, a: int) -> int:
        return (n + a - 1) & ~(a - 1)

    text = bytearray()
    export_rvas: Dict[str, int] = {}
    text_rva = 0x1000

    def emit_code(name: str, asm: str) -> None:
        nonlocal text
        export_rvas[name] = len(text)
        text += _shim_asm(asm)
        while len(text) % 16:
            text.append(0xCC)

    def emit_bytes(name: str, blob: bytes) -> None:
        nonlocal text
        export_rvas[name] = len(text)
        text += blob
        while len(text) % 16:
            text.append(0xCC)

    # DllMain patched after vectored handler + IAT layout are known.
    dllmain_off: Optional[int] = None
    vectored_off: Optional[int] = None

    emit_code('InterlockedExchange',
              'mov eax, edx; lock xchg dword ptr [rcx], eax; ret')
    # GetVDMCurrentDirectories(cch, buf): Win10 native always returns 0.
    # Query (buf==NULL or cch==0) → need 3 bytes; fill → write ".\0\0".
    emit_bytes('GetVDMCurrentDirectories', bytes([
        0x48, 0x85, 0xD2,              # test rdx, rdx
        0x74, 0x14,                    # jz  query
        0x48, 0x85, 0xC9,              # test rcx, rcx
        0x74, 0x0F,                    # jz  query
        0xC6, 0x02, 0x2E,              # mov byte ptr [rdx], '.'
        0xC6, 0x42, 0x01, 0x00,        # mov byte ptr [rdx+1], 0
        0xC6, 0x42, 0x02, 0x00,        # mov byte ptr [rdx+2], 0
        0xB8, 0x03, 0x00, 0x00, 0x00,  # mov eax, 3
        0xC3,                          # ret
    ]))
    # Defer _setjmp3 / longjmp until we know a .text-local nv-save VA
    # (call-align R12–R15 cannot fit in the 0x40-byte VC6 jmp_buf).
    _deferred_seh = {}
    for _seh_name, _seh_blob in _seh_stubs.items():
        if _seh_name in ('_setjmp3', 'longjmp'):
            _deferred_seh[_seh_name] = _seh_blob
            continue
        emit_bytes(_seh_name, _seh_blob)
    if '_except_handler3' not in _seh_stubs:
        emit_code('_except_handler3', 'mov eax, 1; ret')
    if '_seh_longjmp_unwind' not in _seh_stubs:
        emit_code('_seh_longjmp_unwind', 'ret')

    if build_vectored_seh_handler and '_except_handler3' in export_rvas:
        eh3_rva = text_rva + export_rvas['_except_handler3']
        vectored_blob = build_vectored_seh_handler(
            eh3_rva, W2KSHIM_IMAGE_BASE)
        if vectored_blob:
            vectored_off = len(text)
            text += vectored_blob
            while len(text) % 16:
                text.append(0xCC)

    if build_dllmain_install_vectored and vectored_off is not None:
        dllmain_off = len(text)
        export_rvas['DllMain'] = dllmain_off
        text += b'\x90' * 256  # placeholder — patched after .idata layout
        while len(text) % 16:
            text.append(0xCC)
    else:
        emit_code('DllMain', 'mov eax, 1; ret')
    # VirtualQuery x86-ABI wrapper: placeholder patched after .idata layout
    # (needs the real kernel32!VirtualQuery IAT slot VA, like DllMain).
    vq_off: Optional[int] = None
    if (build_virtualquery_shim and build_shim_idata
            and dllmain_off is not None and vectored_off is not None):
        vq_off = len(text)
        export_rvas['VirtualQuery'] = vq_off
        text += b'\xCC' * 192   # placeholder — patched after .idata layout
        while len(text) % 16:
            text.append(0xCC)
    # _get_osfhandle: placeholder — patched once GetStdHandle IAT VA is known.
    gosfh_off: Optional[int] = None
    if (build_get_osfhandle_shim and build_shim_idata
            and dllmain_off is not None and vectored_off is not None):
        gosfh_off = len(text)
        export_rvas['_get_osfhandle'] = gosfh_off
        text += b'\xCC' * 96
        while len(text) % 16:
            text.append(0xCC)
    # CriticalSection guest→host map wrappers (patched after .idata + .data).
    cs_offs: Dict[str, int] = {}
    if (build_cs_init_shim and build_shim_idata
            and dllmain_off is not None and vectored_off is not None):
        for _cs_name, _cs_pad in (
            ('InitializeCriticalSection', 160),
            ('EnterCriticalSection', 128),
            ('LeaveCriticalSection', 128),
            ('DeleteCriticalSection', 160),
        ):
            cs_offs[_cs_name] = len(text)
            export_rvas[_cs_name] = cs_offs[_cs_name]
            text += b'\xCC' * _cs_pad
            while len(text) % 16:
                text.append(0xCC)
    # _adjust_fdiv: MSVC's FPU precision workaround. x86 callers write
    # through the returned pointer, so it must be a valid writable address.
    # Return a pointer to a 16-byte zeroed scratch buffer in .text.
    _adj_fdiv_off = len(text)
    # lea rax, [rip + 16]  ; 16 = distance from end of this insn to scratch buf
    text += b'\x48\x8D\x05\x10\x00\x00\x00'  # lea rax, [rip+16]
    text += b'\xC3'                            # ret
    # 16-byte scratch buffer (aligned by earlier padding)
    text += b'\x00' * 16
    while len(text) % 16:
        text.append(0xCC)
    export_rvas['_adjust_fdiv'] = _adj_fdiv_off

    # Win2000 cmd (and other apps) pass a packed DWORD (two wchars) to
    # towupper/towlower.  The live Win10 msvcrt locale/ctype state inside the
    # translated process is not reliably initialised, so msvcrt's wide path can
    # dereference a stale per-thread/locale pointer and fault (observed
    # towupper(0x3A0043) crashing deep in msvcrt with a string-data pointer in
    # rax).  Provide self-contained stubs that never touch msvcrt state: mask to
    # a single wchar and fold the ASCII a-z/A-Z range.  Universal — every
    # Win2000 binary that uppercases path/drive characters benefits.
    emit_bytes('towupper', bytes((
        0x0F, 0xB7, 0xC1,              # movzx eax, cx
        0x66, 0x83, 0xF8, 0x61,        # cmp ax, 'a'
        0x72, 0x0A,                    # jb  ret
        0x66, 0x83, 0xF8, 0x7A,        # cmp ax, 'z'
        0x77, 0x04,                    # ja  ret
        0x66, 0x83, 0xE8, 0x20,        # sub ax, 0x20
        0xC3)))                        # ret
    emit_bytes('towlower', bytes((
        0x0F, 0xB7, 0xC1,              # movzx eax, cx
        0x66, 0x83, 0xF8, 0x41,        # cmp ax, 'A'
        0x72, 0x0A,                    # jb  ret
        0x66, 0x83, 0xF8, 0x5A,        # cmp ax, 'Z'
        0x77, 0x04,                    # ja  ret
        0x66, 0x83, 0xC0, 0x20,        # add ax, 0x20
        0xC3)))                        # ret

    # Call-align nonvolatiles for setjmp/longjmp (outside VC6 0x40 jmp_buf).
    # Stubs use lea rax,[rip+disp] patched once .data RVA is known — not
    # preferred-base absolute VAs (ASLR) and not .text storage (not writable).
    if build_setjmp3 and build_longjmp:
        emit_bytes('_setjmp3', build_setjmp3(with_nv_save=True))
        emit_bytes('longjmp', build_longjmp(with_nv_save=True))
    elif _deferred_seh:
        for _seh_name, _seh_blob in _deferred_seh.items():
            emit_bytes(_seh_name, _seh_blob)

    # CRT globals must be WRITABLE:
    # __p__fmode() / __p___initenv() and writes through the returned pointer
    # (e.g. *__p__commode() = _commode;). Keeping them in .text (R/X) faults
    # with STATUS_ACCESS_VIOLATION on the store, so they live in .data (R/W).
    data_blob = bytearray()
    commode_data = len(data_blob)
    data_blob += struct.pack('<I', 0)
    fmode_data = len(data_blob)
    data_blob += struct.pack('<I', 0)
    initenv_data = len(data_blob)
    data_blob += struct.pack('<Q', 0)
    # 24-byte call-align NV save for setjmp/longjmp (R12,R14,R15).
    # R13 lives in the jmp_buf at +0x38 (per-buffer) to avoid global races.
    nv_save_data = len(data_blob)
    data_blob += b'\x00' * 24
    # Guest Win32 CS VA → host Win64 CRITICAL_SECTION map.
    cs_map_data = len(data_blob)
    data_blob += b'\x00' * int(CS_MAP_BYTES or 0)

    ptr_thunks: List[Tuple[str, int, int]] = []   # (name, data_off, fn_off)

    def emit_ptr_thunk(name: str, data_off: int) -> None:
        nonlocal text
        fn_off = len(text)
        export_rvas[name] = fn_off
        # 48 8D 05 <disp32> = lea rax,[rip+disp]; disp patched once data_rva known
        text.extend(b'\x48\x8D\x05')
        text.extend(struct.pack('<i', 0))
        text.append(0xC3)
        ptr_thunks.append((name, data_off, fn_off))
        while len(text) % 16:
            text.append(0xCC)

    emit_ptr_thunk('__p__commode', commode_data)
    emit_ptr_thunk('__p__fmode', fmode_data)
    emit_ptr_thunk('__p___initenv', initenv_data)

    data_rva = align(text_rva + len(text), SECT_ALIGN)
    for _name, data_off, fn_off in ptr_thunks:
        disp = (data_rva + data_off) - (text_rva + fn_off + 7)
        struct.pack_into('<i', text, fn_off + 3, disp)
    if patch_nv_save_lea and '_setjmp3' in export_rvas and 'longjmp' in export_rvas:
        nv_rva = data_rva + nv_save_data
        for _sj_name in ('_setjmp3', 'longjmp'):
            _sj_off = export_rvas[_sj_name]
            # Find end of this stub in text (next export or pad) — patch in place.
            _end = len(text)
            for _other, _ooff in export_rvas.items():
                if _ooff > _sj_off and _ooff < _end:
                    _end = _ooff
            _blob = text[_sj_off:_end]
            if patch_nv_save_lea(_blob, _sj_off, nv_rva, text_rva):
                text[_sj_off:_sj_off + len(_blob)] = _blob

    idata_rva = 0
    idata_blob = b''
    import_dir_size = 0
    if build_shim_idata and dllmain_off is not None and vectored_off is not None:
        idata_rva = align(data_rva + len(data_blob), SECT_ALIGN)
        _idata = build_shim_idata(text_rva, idata_rva)
        # Compat: older 4/5-tuple vs CS-extended 9-tuple.
        initcs_iat_rva = entercs_iat_rva = leavecs_iat_rva = None
        deletecs_iat_rva = None
        if len(_idata) >= 9:
            (idata_blob, iat_slot_rva, seterr_iat_rva,
             vq_iat_rva, getstd_iat_rva,
             initcs_iat_rva, entercs_iat_rva, leavecs_iat_rva,
             deletecs_iat_rva) = _idata[:9]
        elif len(_idata) == 5:
            (idata_blob, iat_slot_rva, seterr_iat_rva,
             vq_iat_rva, getstd_iat_rva) = _idata
        else:
            (idata_blob, iat_slot_rva, seterr_iat_rva,
             vq_iat_rva) = _idata
            getstd_iat_rva = None
        import_dir_size = len(idata_blob)
        dm = build_dllmain_install_vectored(
            text_rva + vectored_off, W2KSHIM_IMAGE_BASE, iat_slot_rva,
            text_rva + export_rvas['_except_handler3'], seterr_iat_rva)
        if len(dm) <= 256:
            text[dllmain_off:dllmain_off + len(dm)] = dm
            for trap in range(len(dm), 240, 16):
                rel = -(trap + 5)
                text[dllmain_off + trap:dllmain_off + trap + 5] = (
                    b'\xE9' + struct.pack('<i', rel))
        else:
            raise RuntimeError(
                f'w2kshim64 DllMain stub {len(dm)} bytes exceeds 256-byte slot')
        if vq_off is not None:
            vq_blob = build_virtualquery_shim(W2KSHIM_IMAGE_BASE + vq_iat_rva)
            if len(vq_blob) <= 192:
                text[vq_off:vq_off + len(vq_blob)] = vq_blob
            else:
                raise RuntimeError(
                    f'w2kshim64 VirtualQuery stub {len(vq_blob)} bytes '
                    f'exceeds 192-byte slot')
        if gosfh_off is not None and build_get_osfhandle_shim is not None:
            if getstd_iat_rva is None:
                raise RuntimeError(
                    'w2kshim64 _get_osfhandle requires GetStdHandle IAT slot')
            gosfh_blob = build_get_osfhandle_shim(
                W2KSHIM_IMAGE_BASE + getstd_iat_rva)
            if len(gosfh_blob) <= 96:
                text[gosfh_off:gosfh_off + len(gosfh_blob)] = gosfh_blob
            else:
                raise RuntimeError(
                    f'w2kshim64 _get_osfhandle stub {len(gosfh_blob)} bytes '
                    f'exceeds 96-byte slot')
        if cs_offs and initcs_iat_rva is not None:
            map_va = W2KSHIM_IMAGE_BASE + data_rva + cs_map_data
            _cs_builders = (
                ('InitializeCriticalSection', build_cs_init_shim,
                 initcs_iat_rva, 160),
                ('EnterCriticalSection', build_cs_enter_shim,
                 entercs_iat_rva, 128),
                ('LeaveCriticalSection', build_cs_leave_shim,
                 leavecs_iat_rva, 128),
                ('DeleteCriticalSection', build_cs_delete_shim,
                 deletecs_iat_rva, 160),
            )
            for _cs_name, _cs_build, _cs_iat, _cs_pad in _cs_builders:
                if _cs_name not in cs_offs or _cs_build is None or _cs_iat is None:
                    continue
                _cs_blob = _cs_build(map_va, W2KSHIM_IMAGE_BASE + _cs_iat)
                if len(_cs_blob) > _cs_pad:
                    raise RuntimeError(
                        f'w2kshim64 {_cs_name} stub {len(_cs_blob)} bytes '
                        f'exceeds {_cs_pad}-byte slot')
                _off = cs_offs[_cs_name]
                text[_off:_off + len(_cs_blob)] = _cs_blob

    text = bytes(text)
    data_blob = bytes(data_blob)

    export_names = [
        'DllMain', 'InterlockedExchange',
        '_setjmp3', 'longjmp',
        '_except_handler3', '_seh_longjmp_unwind',
        '_adjust_fdiv', '__p___initenv',
        '__p__commode', '__p__fmode',
        'towupper', 'towlower',
    ]
    if 'VirtualQuery' in export_rvas:
        export_names.append('VirtualQuery')
    if '_get_osfhandle' in export_rvas:
        export_names.append('_get_osfhandle')
    if 'GetVDMCurrentDirectories' in export_rvas:
        export_names.append('GetVDMCurrentDirectories')
    for _cs_name in (
        'InitializeCriticalSection', 'EnterCriticalSection',
        'LeaveCriticalSection', 'DeleteCriticalSection',
    ):
        if _cs_name in export_rvas:
            export_names.append(_cs_name)
    names_blob = bytearray()
    name_offs: List[int] = []
    for nm in export_names:
        name_offs.append(len(names_blob))
        names_blob += nm.encode('ascii') + b'\x00'

    nexports = len(export_names)
    hdr = 40
    func_tbl = hdr
    name_ptr = func_tbl + nexports * 4
    ord_tbl = name_ptr + nexports * 4
    names_sec = ord_tbl + nexports * 2
    dll_name_off = names_sec + len(names_blob)
    edata_size = dll_name_off + len(W2KSHIM_DLL_NAME) + 1

    edata_rva = align(
        (idata_rva + len(idata_blob)) if idata_blob else (data_rva + len(data_blob)),
        SECT_ALIGN)
    edata = bytearray(b'\x00' * edata_size)
    edata[names_sec:names_sec + len(names_blob)] = names_blob
    dll_nm = W2KSHIM_DLL_NAME.encode('ascii') + b'\x00'
    edata[dll_name_off:dll_name_off + len(dll_nm)] = dll_nm

    name_ptr_base = edata_rva + names_sec
    struct.pack_into('<IIHHIIIIIII', edata, 0,
                     0, 0,
                     0, 0,
                     edata_rva + dll_name_off,
                     1, nexports, nexports,
                     edata_rva + func_tbl,
                     edata_rva + name_ptr,
                     edata_rva + ord_tbl)

    for i, nm in enumerate(export_names):
        struct.pack_into('<I', edata, func_tbl + i * 4, text_rva + export_rvas[nm])

    # AddressOfNames must be sorted ascending by ASCII name (strcmp order).
    sorted_names = sorted(export_names)
    for i, nm in enumerate(sorted_names):
        struct.pack_into('<I', edata, name_ptr + i * 4, name_ptr_base + name_offs[export_names.index(nm)])
        func_idx = export_names.index(nm)
        struct.pack_into('<H', edata, ord_tbl + i * 2, func_idx + 1)  # ordinal = base(1) + index

    sections = [
        ('.text', text, 0xE0000020, text_rva),
        ('.data', data_blob, 0xC0000040, data_rva),
    ]
    if idata_blob:
        sections.append(('.idata', idata_blob, 0xC0000040, idata_rva))
    sections.append(('.edata', bytes(edata), 0x40000040, edata_rva))
    num_sections = len(sections)
    PE64_OPT = PE64_OPT_TOTAL
    hdrs_size = align(64 + 4 + 20 + PE64_OPT + num_sections * 40, FILE_ALIGN)
    image_size = align(edata_rva + len(edata), SECT_ALIGN)

    dos = b'MZ' + b'\x00' * 0x3A + struct.pack('<I', 0x40)
    pe_sig = b'PE\x00\x00'
    coff = struct.pack('<HHIIIHH',
                       0x8664, num_sections, 0, 0, 0,
                       PE64_OPT, 0x2102)   # DLL | EXECUTABLE

    opt_hdr = struct.pack('<HBBI', 0x020B, 14, 0, align(len(text), FILE_ALIGN))
    opt_hdr += struct.pack('<III',
                           sum(align(len(s[1]), FILE_ALIGN) for s in sections[1:]),
                           0,
                           text_rva + export_rvas['DllMain'])
    opt_hdr += struct.pack('<IQ', text_rva, W2KSHIM_IMAGE_BASE)
    opt_hdr += struct.pack('<IIHHHHHH', SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0)
    opt_hdr += struct.pack('<IIII', 0, image_size, hdrs_size, 0)
    opt_hdr += struct.pack('<HH', 3, 0x0100)   # DLL subsystem, NX only (fixed ImageBase)
    opt_hdr += struct.pack('<QQQQ', 0x100000, 0x1000, 0x100000, 0x1000)
    opt_hdr += struct.pack('<II', 0, 16)
    if len(opt_hdr) != PE64_OPT_STD:
        raise RuntimeError(
            f"w2kshim64 opt header: expected {PE64_OPT_STD}, got {len(opt_hdr)}")

    data_dirs = b''
    for idx in range(16):
        if idx == 0:
            data_dirs += struct.pack('<II', edata_rva, len(edata))
        elif idx == 1 and idata_blob:
            data_dirs += struct.pack('<II', idata_rva, import_dir_size)
        else:
            data_dirs += struct.pack('<II', 0, 0)

    sect_hdrs = b''
    file_ptr = hdrs_size
    for sname, sdata, sflags, sva in sections:
        raw_sz = align(len(sdata), FILE_ALIGN)
        n = sname.encode('ascii', 'replace')[:8].ljust(8, b'\x00')
        sect_hdrs += struct.pack('<8sIIIIIIHHI',
                                 n, len(sdata), sva, raw_sz, file_ptr,
                                 0, 0, 0, 0, sflags)
        file_ptr += raw_sz

    header_blob = dos + pe_sig + coff + opt_hdr + data_dirs + sect_hdrs
    header_blob = header_blob.ljust(hdrs_size, b'\x00')
    out = bytearray(header_blob)
    for _, sdata, _, _ in sections:
        out += sdata.ljust(align(len(sdata), FILE_ALIGN), b'\x00')
    # Update the canonical _env binding — ``from _env import *`` only gave
    # this module a local name; writers of EH3 absolute VAs read _env.
    from x86x64.translator import _env as _w2k_env
    _w2k_env.W2KSHIM_EXCEPT_HANDLER3_RVA = text_rva + export_rvas.get(
        '_except_handler3', 0x10C0 - text_rva)
    global W2KSHIM_EXCEPT_HANDLER3_RVA
    W2KSHIM_EXCEPT_HANDLER3_RVA = _w2k_env.W2KSHIM_EXCEPT_HANDLER3_RVA
    return bytes(out)
def ensure_w2kshim_dll(out_dir: str) -> str:
    """Write w2kshim64.dll into out_dir (always refresh — small dev-test helper)."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, W2KSHIM_DLL_NAME)
    blob = build_w2kshim64_dll()
    with open(path, 'wb') as f:
        f.write(blob)
    return path
