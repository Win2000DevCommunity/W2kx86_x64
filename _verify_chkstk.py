"""Post-build verification for the exact-allocation chkstk fix.

Checks in the FINAL binary:
  1. __chkstk helper tail = mov rax,[rsp+8]; sub ecx,8; mov esp,ecx; push rax; ret
     (NO `and ecx,-16`).
  2. The 0xA4E7-function epilogue `add rsp,N` = exact x86 size 0x2464.
  3. Deep read [rsp+0x248c] present at 0x4A34C.
Usage: python _verify_chkstk.py build_univ374
"""
import sys, struct

GOOD_OLD = bytes.fromhex('488b44240883e1f089cc50c3')  # and ecx,-16 form
GOOD_NEW = bytes.fromhex('488b4424088d49f889cc50c3')  # lea ecx,[ecx-8] exact form

def load(path):
    f = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', f, 0x3C)[0]
    nsec = struct.unpack_from('<H', f, e_lfanew + 6)[0]
    opt = e_lfanew + 24
    sec = opt + struct.unpack_from('<H', f, e_lfanew + 20)[0]
    for i in range(nsec):
        off = sec + i * 40
        name = f[off:off + 8].rstrip(b'\x00')
        vs, va, rs, ra = struct.unpack_from('<IIII', f, off + 8)
        if name == b'.text':
            return f, va, ra
    raise SystemExit('no .text')

def blob_off(binpath, rva):
    f, va, ra = load(binpath)
    return f[ra + (rva - va):]

if __name__ == '__main__':
    build = sys.argv[1]
    exe = build + r'\cmd_pure.exe'
    f, va, ra = load(exe)
    blob = f[ra:ra + 0x70000]

    # 1. helper tail
    i_new = blob.find(GOOD_NEW)
    i_old = blob.find(GOOD_OLD)
    print('helper NEW tail found at', hex(i_new) if i_new >= 0 else 'MISSING')
    print('helper OLD tail found at', hex(i_old) if i_old >= 0 else 'none (good)')

    # find chkstk entry (cmp eax,0x1000 followed by lea rcx,[rsp+0x10])
    ck = blob.find(bytes.fromhex('3d00100000488d4c241051'))
    print('chkstk entry sig at', hex(ck) if ck >= 0 else 'MISSING')

    # 2. epilogue add at 0x4A35A: 48 81 C4 imm32 after pop rdi/rsi/rbp/rbx
    off = 0x400 + (0x4A356 - 0x1000)
    tail = f[off:off + 0x20]
    print('epilogue bytes:', tail.hex())
    if tail[:4] == bytes.fromhex('5f5e5d5b') and tail[4:7] == b'\x48\x81\xc4':
        imm = struct.unpack_from('<I', tail, 7)[0]
        print('epilogue add rsp =', hex(imm), 'expected 0x2464',
              'OK' if imm == 0x2464 else 'WRONG')

    # 3. deep read at 0x4A34C
    off = 0x400 + (0x4A34C - 0x1000)
    print('deep read bytes:', f[off:off + 7].hex(),
          'OK' if f[off:off + 7] == bytes.fromhex('8b84248c240000') else 'check')

    # 4. count all add rsp,imm32 after pop-runs near chkstk callers
    import re
    adds = [m.start() for m in re.finditer(rb'\x48\x81\xc4', blob)]
    print('total add rsp,imm32 sites:', len(adds))
