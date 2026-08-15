"""HW+INT3 bp: park r12, call r12, after call; TF until execute AV."""
import ctypes as C
import struct
import sys
import os
from ctypes import wintypes
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, ".")
import dbg_fault as df

k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()

CONTEXT_DEBUG = df.CONTEXT_AMD64 | 0x10
CONTEXT_ALL = df.CONTEXT_FULL | CONTEXT_DEBUG

EXE = os.path.abspath(r"build_univ256\cmd_probe_ecx.exe")
IB = 0x80000000
BP_AFTER = 0x18E56
BP_CALL  = 0x18E53
BP_PARK  = 0x18BAC

md = Cs(CS_ARCH_X86, CS_MODE_64)

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer(f'"{EXE}" /c echo w2ktest')
assert k32.CreateProcessW(
    EXE, cmd, None, None, False,
    df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE),
    C.byref(si), C.byref(pi))

base = IB
tracing = False
steps = []
MAX_STEPS = 1200
last_xfer = None
hit_after = 0
hit_call = 0
hit_park = 0
orig = {}
soft_bps = {}
callee_bp = None
de = df.DEBUG_EVENT()


def get_ctx(ht):
    ctx = df.CONTEXT()
    ctx.ContextFlags = CONTEXT_ALL
    k32.GetThreadContext(ht, C.byref(ctx))
    return ctx


def set_ctx(ht, ctx):
    ctx.ContextFlags = CONTEXT_ALL
    k32.SetThreadContext(ht, C.byref(ctx))


def is_code(addr):
    return base <= addr < base + 0x80000


def dis_at(rip, n=16):
    raw = df.read_process_mem(pi.hProcess, rip, n)
    if not raw:
        return None, "?"
    for insn in md.disasm(raw, rip):
        return insn, f"{insn.mnemonic} {insn.op_str}"
    return None, raw[:8].hex()


def dump_regs(ctx, tag):
    print(f"--- {tag} ---")
    print(f"  RIP={ctx.Rip:#x} rva={(ctx.Rip-base)&0xffffffff:#x}")
    print(f"  RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} RBX={ctx.Rbx:#x}")
    print(f"  RSP={ctx.Rsp:#x} RBP={ctx.Rbp:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x}")
    print(f"  R12={ctx.R12:#x} R13={ctx.R13:#x} R14={ctx.R14:#x} R15={ctx.R15:#x}")
    for off in range(0, 0x40, 8):
        v = df.read_u64(pi.hProcess, ctx.Rsp + off)
        tag2 = f" code={(v-base):#x}" if v and is_code(v) else ("" if not v or v < 0x10000 else " ptr")
        print(f"  [rsp+{off:#x}]={v:#x}{tag2}")


def arm_hw(ctx, after=True, call=True):
    ctx.Dr0 = (base + BP_CALL) if call else 0
    ctx.Dr1 = (base + BP_AFTER) if after else 0
    ctx.Dr2 = base + BP_PARK
    ctx.Dr3 = 0
    en = 0
    if call: en |= 0x1
    if after: en |= 0x4
    en |= 0x10  # DR2
    ctx.Dr7 = en
    ctx.Dr6 = 0


def patch_soft(addr, name):
    b = df.read_process_mem(pi.hProcess, addr, 1)
    if not b:
        print("soft bp read fail", name, hex(addr)); return
    orig[addr] = b[0]
    soft_bps[addr] = name
    df.patch_byte(pi.hProcess, addr, 0xCC)
    print(f"softBP {name} @ {addr:#x} was {b[0]:02x}")


while k32.WaitForDebugEvent(C.byref(de), 30000):
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage or IB
        print(f"base={base:#x}")
        ctx = get_ctx(pi.hThread)
        arm_hw(ctx)
        set_ctx(pi.hThread, ctx)
        # also soft BPs as backup
        for rva, name in ((BP_CALL, "call_r12"), (BP_AFTER, "after_r12"), (BP_PARK, "park")):
            patch_soft(base + rva, name)
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)

    elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        code = er.ExceptionCode & 0xFFFFFFFF
        addr = int(er.ExceptionAddress or 0)

        if code == 0x80000003:
            # software BP
            bp_addr = addr if addr in orig else (addr - 1 if (addr - 1) in orig else None)
            # ntdll initial
            if bp_addr is None and addr < 0x10000:
                pass
            elif bp_addr is not None:
                name = soft_bps.get(bp_addr, "?")
                ctx = get_ctx(pi.hThread)
                # restore
                df.patch_byte(pi.hProcess, bp_addr, orig[bp_addr])
                ctx.Rip = bp_addr
                dump_regs(ctx, f"SOFT {name}")

                if name == "park":
                    hit_park += 1
                    print(f"  park rax={ctx.Rax:#x} is_code={is_code(ctx.Rax)}")
                    # plant soft BP at callee entry
                    if is_code(ctx.Rax) and ctx.Rax not in orig:
                        patch_soft(ctx.Rax, "callee_entry")
                        callee_bp = ctx.Rax
                    # re-arm after single step
                    ctx.EFlags |= 0x100
                    arm_hw(ctx)
                    set_ctx(pi.hThread, ctx)
                    # will re-patch park on SS? one-shot park OK

                elif name == "call_r12":
                    hit_call += 1
                    print(f"  call r12 -> {ctx.R12:#x} is_code={is_code(ctx.R12)}")
                    if not is_code(ctx.R12):
                        print("*** r12 NON-CODE at call")
                        last_xfer = ({"rva": BP_CALL, "text": "call r12",
                                      "rbx": ctx.Rbx, "rsi": ctx.Rsi,
                                      "r12": ctx.R12, "rsp": ctx.Rsp},
                                     ctx.R12, "call r12")
                    ctx.EFlags |= 0x10000  # RF
                    arm_hw(ctx)
                    set_ctx(pi.hThread, ctx)

                elif name == "after_r12":
                    hit_after += 1
                    print(f"  AFTER call r12 rax={ctx.Rax:#x}")
                    tracing = True
                    steps.clear()
                    arm_hw(ctx, after=False)
                    ctx.EFlags |= 0x100
                    set_ctx(pi.hThread, ctx)

                elif name == "callee_entry":
                    print(f"  CALLEE entry rip={ctx.Rip:#x}")
                    dump_regs(ctx, "callee")
                    # start tracing from callee to find heap xfer
                    tracing = True
                    steps.clear()
                    arm_hw(ctx, after=True, call=True)
                    ctx.EFlags |= 0x100
                    set_ctx(pi.hThread, ctx)

                else:
                    ctx.EFlags |= 0x10000
                    set_ctx(pi.hThread, ctx)
            else:
                print(f"other int3 @ {addr:#x}")
                cont = df.DBG_EXCEPTION_NOT_HANDLED

        elif code == 0x80000004:
            ctx = get_ctx(pi.hThread)
            dr6 = ctx.Dr6
            if tracing:
                insn, text = dis_at(ctx.Rip)
                rva = (ctx.Rip - base) & 0xffffffff
                entry = dict(rva=rva, rip=ctx.Rip, text=text,
                             rax=ctx.Rax, rbx=ctx.Rbx, rcx=ctx.Rcx,
                             rsi=ctx.Rsi, rdi=ctx.Rdi, rsp=ctx.Rsp,
                             rbp=ctx.Rbp, r12=ctx.R12)
                steps.append(entry)

                tgt = None
                if insn and insn.mnemonic.startswith("ret"):
                    tgt = df.read_u64(pi.hProcess, ctx.Rsp)
                elif insn and insn.mnemonic in ("call", "jmp"):
                    for nm, val in (("rax", ctx.Rax), ("rbx", ctx.Rbx),
                                    ("rcx", ctx.Rcx), ("rdx", ctx.Rdx),
                                    ("rsi", ctx.Rsi), ("rdi", ctx.Rdi),
                                    ("r8", ctx.R8), ("r9", ctx.R9),
                                    ("r10", ctx.R10), ("r11", ctx.R11),
                                    ("r12", ctx.R12), ("r13", ctx.R13),
                                    ("r14", ctx.R14), ("r15", ctx.R15)):
                        if nm in insn.op_str.split(",")[0] or insn.op_str.strip() == nm:
                            tgt = val
                            break
                    # call qword ptr [..] — try common patterns later
                    if tgt is None and "qword ptr" in insn.op_str:
                        # best-effort: if [rbx] etc
                        pass

                if tgt is not None and tgt > 0x10000 and not is_code(tgt):
                    last_xfer = (entry, tgt, text)
                    print(f"*** XFER `{text}` -> {tgt:#x} at rva={rva:#x}")
                    dump_regs(ctx, "BEFORE bad xfer")

                if (insn and insn.mnemonic in ("call", "jmp", "ret", "retn", "leave")) \
                        or len(steps) <= 5 or len(steps) % 50 == 0:
                    in_main = is_code(ctx.Rip)
                    loc = f"{rva:#06x}" if in_main else f"ext:{ctx.Rip:#x}"
                    print(f"  [{len(steps)}] {loc}: {text}  "
                          f"rbx={ctx.Rbx:#x} rsi={ctx.Rsi:#x} rax={ctx.Rax:#x} rsp={ctx.Rsp:#x}")

                if len(steps) >= MAX_STEPS:
                    print("MAX_STEPS")
                    dump_regs(ctx, "max")
                    k32.TerminateProcess(pi.hProcess, 1)
                    break

                # re-arm soft BPs we one-shot? after_r12 already consumed
                arm_hw(ctx, after=False, call=False)
                ctx.Dr6 = 0
                ctx.EFlags |= 0x100
                set_ctx(pi.hThread, ctx)

            elif dr6 & 7:
                which = []
                if dr6 & 1: which.append("HW_call")
                if dr6 & 2: which.append("HW_after")
                if dr6 & 4: which.append("HW_park")
                dump_regs(ctx, "+".join(which))
                if dr6 & 1:
                    hit_call += 1
                    print(f"  HW call r12={ctx.R12:#x}")
                if dr6 & 2:
                    hit_after += 1
                    tracing = True
                    steps.clear()
                    ctx.EFlags |= 0x100
                if dr6 & 4:
                    hit_park += 1
                    print(f"  HW park rax={ctx.Rax:#x}")
                ctx.Dr6 = 0
                arm_hw(ctx, after=not tracing)
                if tracing:
                    ctx.EFlags |= 0x100
                else:
                    ctx.EFlags |= 0x10000
                set_ctx(pi.hThread, ctx)
            else:
                # re-patch one-shot soft after SS if needed — skip
                pass

        elif code == 0xC0000005:
            ctx = get_ctx(pi.hThread)
            info0 = er.ExceptionInformation[0] if er.NumberParameters > 0 else 0
            kind = {0: "read", 1: "write", 8: "execute"}.get(info0, str(info0))
            print(f"\n===== AV {kind} @ {addr:#x} =====")
            dump_regs(ctx, "AV")
            print(f"hits park={hit_park} call={hit_call} after={hit_after} steps={len(steps)}")
            if steps:
                print("last 20 steps:")
                for s in steps[-20:]:
                    print(f"  {s['rva']:#06x}: {s['text']}  "
                          f"rbx={s['rbx']:#x} rsi={s['rsi']:#x} rax={s['rax']:#x} rsp={s['rsp']:#x}")
            if last_xfer:
                e, t, text = last_xfer
                print(f"\nLAST BAD XFER: `{text}` -> {t:#x} rva={e.get('rva'):#x}")
            # find step where rbx became heap or ctrl to AV addr
            for s in reversed(steps):
                mn = s["text"].split()[0] if s["text"] else ""
                if mn in ("call", "jmp", "ret", "retn"):
                    print(f"last ctrl step: {s['rva']:#x}: {s['text']} "
                          f"rbx={s['rbx']:#x} rsi={s['rsi']:#x}")
                    break
            k32.TerminateProcess(pi.hProcess, 1)
            break
        else:
            cont = df.DBG_EXCEPTION_NOT_HANDLED

    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode)
        break

    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)

print(f"done park={hit_park} call={hit_call} after={hit_after}")
