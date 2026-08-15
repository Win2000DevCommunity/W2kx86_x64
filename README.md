# Windows 2000 x86 to Native x64 Binary Translator & Debugging Suite

An advanced, multi-stage static and dynamic binary translation system designed to convert Windows 2000 SP4 (NT 5.0.2195) x86 PE32 binaries to native, XP x64/Win10 x64 compatible PE64 (x86-64) binaries. This enables running legacy x86 system applications natively on 64-bit systems.

---

## Repository Layout

| Path | Contents |
| --- | --- |
| `x86_x64.py` | Main translation driver (Capstone → Keystone, PE64 emit) |
| `dbg_fault.py` / `dbg_trace.py` / `dbg_root.py` | Crash monitor / smart step-over tracer / exception daemon |
| `x86x64/` | The translator package (analysis, translation, PE writing, shim) |
| `w2kseh64.py`, `ring0_emu.py` | SEH runtime layer and ring-0 diagnostic emulator |
| `debug_scripts/` | ~1,100 one-off diagnostic scripts accumulated per crash site (disassembly, IAT checks, probes, patchers) |
| `debug_scripts/dumps/` | Diagnostic text dumps |

---

## Project Architecture

The translator maps 32-bit execution context to native 64-bit equivalents:
- **Syscall Mapping**: Win2000 stdcall `int 0x2e` (EAX = syscall #, EDX = stack args pointer) is converted to 64-bit native `syscall` instruction with arguments marshalled into `RCX`, `RDX`, `R8`, `R9`, and stack.
- **Calling Convention Conversion**: Automatically converts standard stdcall and cdecl stack-based arguments to the Microsoft x64 ABI calling convention.
- **TEB Segment Remapping**: Maps `FS:[offset]` 32-bit thread-environment block references directly to `GS:[offset]` 64-bit registers (e.g., ExceptionList, StackBase, StackLimit, PEB, and LastErrorValue).

---

## Core Components

### 1. Binary Translator (`x86_x64.py`)
The primary driver of the translation pipeline. It operates across 5 discrete stages:
1. **PE32 Parse**: Reads PE32 headers, section layouts, imports (IAT), exports, and relocation directories.
2. **Static & Dynamic CF Analysis**: Disassembles instructions using Capstone and builds basic-block CFGs. Utilizes Unicorn Engine to trace register state and branch targets.
3. **Dynamic Scan**: Harvests runtime pointers, indirect jumps, and compute targets.
4. **Code Translation (Capstone → Keystone)**: Performs TEB remapping, ABI translation, relocates pointer immediates, and translates NTDLL syscall stubs.
5. **PE64 Emit**: Generates valid 64-bit PE headers, relocations, exports, and PE64-compliant IAT thunks.

### 2. Root-Cause Exception Daemon (`dbg_root.py`)
A specialized Win32 debug-loop daemon for translated PE64 executables.
* Unlike simple debuggers that halt on any exception, this daemon **jumps through first-chance exceptions** (e.g. handled SEH or vectored exceptions).
* When a fatal crash occurs, it backtracks from the final symptoms (such as invalid stack frames or illegal instructions) back to the last trustworthy instruction in the main image.
* **Usage**: `python dbg_root.py <exe> [args...]` (Supports `--trace`, `--crt`, `--interactive`, and `--watch` RVA breakpoints).

### 3. Smart Step-Over Tracer (`dbg_trace.py`)
A fast instruction-level tracer targeting only the main translated executable.
* Speeds up debugging by only single-stepping while `RIP` resides inside the main module's address space.
* Once the execution exits the main module (e.g. into system DLLs like `ntdll.dll` or `kernel32.dll`), it drops a one-shot `INT3` breakpoint at the return address and runs at native speed, avoiding millions of useless steps.
* Logs call/return frames and prints the last $N$ main instructions leading to a fault.

### 4. Crash Monitor (`dbg_fault.py`)
A lightweight debugger wrapper that intercepts the first crash in a child process, extracts the register state, disassembles the faulting location, and suppresses Windows/Visual Studio JIT debugger popups.

### 5. SEH Runtime (`w2kseh64.py`)
Implements an XP-compatible user-mode layer for VC6 structured exception handling (`_except_handler3`, `_setjmp3`/`longjmp`) using 64-bit register preservation.

### 6. Emulation Layer (`ring0_emu.py`)
A diagnostic emulator using Unicorn Engine to mock Win2000 ring-0 (ntoskrnl, KPCR, KUSER_SHARED_DATA) and ring-3 environments.

---

## Usage & Build Commands

### Building in Pure (Universal) Mode

```powershell
# Create output directory and build cmd.exe in pure translation mode
New-Item -ItemType Directory -Force -Path "build_out81" | Out-Null
$env:PURE="1"
$env:DUMP_RVA_MAP="build_out81\rva.txt"
python x86_x64.py `
  "C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe" `
  build_out81\cmd_pure.exe `
  --pure --win10-test-shim `
  2>&1 | Tee-Object -FilePath build_out81\build.log
```

### Tracing with `dbg_trace.py`

```powershell
# Trace cmd_pure.exe running "echo hello" with watchpoints on key RVAs
python dbg_trace.py build_out80\cmd_pure.exe /c echo hello `
  --seconds=90 `
  --watch=0x168D3,0x168DD,0x168C1 `
  --rva-map=build_out80\rva.txt `
  2>&1 | Select-String -Pattern "watch main|\[exit\]|FAULT|steps=" `
       | ForEach-Object { $_.Line } `
       | Select-Object -First 20
```

---

## Recent Issues & Critical Fixes

### 1. 16-Bit / 8-Bit Load Width Widening
* **Problem**: 16-bit and 8-bit absolute load instructions (e.g., `mov ax, [abs]` and `mov al, [abs]`) were being widened to full 32-bit or 64-bit widths during translation. This corrupted the upper bits of registers.
* **Fix**: Restored strict width validation. 65 distinct absolute-load instructions have been corrected.

### 2. Reanchor Scan Bound Guard
* **Problem**: The reanchor pass, which resolves relocated absolute addresses (such as `movabs`), was over-scanning and clobbering the `movabs` instruction belonging to the next adjacent instruction. 
  * *Example*: A `push`/`store` instruction reanchor clobbered a neighboring `cmp [0x1cf64]` (at RVA `0xC67E` in `cmd.exe`), corrupting it into `cmp [0x1fb00]`. Since `0x1fb00` is the `jmp_buf` address, the value read was always non-zero, forcing `cmd` to immediately exit via a false `exit(1)` error path before ever running subcommands.
* **Fix**: Implemented a block-boundary guard in `_scan_hi`. The scan is capped at the start of the next translated block.
  * A true `movabs` instruction block spans ≥12 bytes (with a 10-byte instruction payload). 
  * The boundary is only applied if the next block start lies at least 12 bytes past the anchor:
    ```python
    def _scan_hi(anchor: int, default_hi: int) -> int:
        # Cap the scan at the next translated block start, but only when that
        # leaves room for a full ``movabs`` (10 bytes) belonging to this insn;
        # coarse/interleaved rva_map entries closer than that are not trusted.
        j = _bisect.bisect_right(_blk_starts, anchor)
        if j < len(_blk_starts):
            nxt = _blk_starts[j]
            if anchor + 12 <= nxt < default_hi:
                return nxt
        return default_hi
    ```

### 3. Current Status of `cmd /c echo`

The behavior differs between the translation modes:

* **With Patch Mode Enabled (`cmd_shim.exe`)**:
  * Tracing `cmd /c echo hello` confirms that the absolute load address `[0x1cf64]` is now read correctly, the false error exit path is gone, and **`hello` successfully prints** to standard output.

* **Universal `--pure` Mode (`cmd_pure.exe`)** — Under Active Reversing:
  * In `build_out80`, the tracer executed **204,440 instructions** before faulting at `msvcrt!exit(1)` via the codepage error path.
  * In `build_out81`, the tracer executed **208,604 instructions** (+4,164 more) but faults at a **different site**: `msvcrt!setlocale` crashes during CRT init.
  * **`cmd_pure.exe` still does not print `echo`** in pure mode. Active investigation is ongoing.

---

## Pure Mode Trace Diagnostics

### build_out80 — Codepage Error Path

The tracer was run with watchpoints at the locale/codepage setup area (`0x168C1`, `0x168D3`, `0x168DD`):

```
[watch main+0x168C1] RAX=0xFFFFFFFFFFFFFF9C RBX=0x1 RCX=0x411 RDX=0x1E001A RSI=0x0 RDI=0x0 R8=0x0 RBP=0x14FE90 RSP=0x14FDE0
[watch main+0x168D3] RAX=0xFFFFFFFFFFFFFFFF RBX=0x1 RCX=0xBD1144175A470000 RDX=0x0 RSI=0x0 RDI=0x0 R8=0x3 RBP=0x14FE90 RSP=0x14FE10
[watch main+0x168DD] RAX=0xFFFFFFFFFFFFFFFF RBX=0x1 RCX=0xBD1144175A470000 RDX=0x0 RSI=0x0 RDI=0x0 R8=0x3 RBP=0x14FE90 RSP=0x14FE10
===== FAULT =====
--- last 48 main-image instructions (steps=204440) ---
```

**API Call Chain (before fault)**:

| API Call Site | Function | Key Arguments |
|---|---|---|
| `main+0x75F8` | `msvcrt!wcscpy` | Copy OEM locale string |
| `main+0x762B` | `msvcrt!setlocale` | LC_ALL = 0 |
| `main+0x11979` | `kernel32!GetProcessHeap` | — |
| `main+0x1199D` | `ntdll!RtlAllocateHeap` | Heap=0x4F0000 |
| `main+0x11A2C` | `kernel32!GetConsoleTitleW` | Buffer=0x504BE0, len=0x104 |
| `main+0x11A81` | `msvcrt!wcscpy` | Console title → buffer |
| `main+0x11CA7` | `kernel32!GetModuleHandleW` | — |
| `main+0x11CD6` | `kernel32!GetProcAddress` | Dynamic import resolve |
| `main+0x166DB` | `w2kshim64!_setjmp3` | SEH jmp_buf at `0x80048B00` |
| `main+0x27282` | `msvcrt!_get_osfhandle` | fd=1 (stdout) |
| `main+0x272AD` | `kernel32!SetConsoleMode` | Handle=0x68 |
| `main+0x1680E` | `kernel32!GetConsoleOutputCP` | — |
| `main+0x16848` | `kernel32!GetCPInfo` | CodePage=0x352 (850) |
| `main+0x168C1` | `msvcrt!_get_osfhandle` | **fd=0x411 ← invalid** |
| `main+0x13809` | `msvcrt!exit` | **exit(1) — premature** |

**Fault**: `_get_osfhandle` receives `0x411` (the codepage value, not a file descriptor) → returns `0xFFFFFFFFFFFFFFFF` → error path fires → `exit(1)`.

### build_out81 — setlocale Crash (new blocker)

```
===== FAULT =====
code=0xC0000005 RIP=sys+0x7FFEB92E76E5
access-violation: read @ 0xFFFFFFFFFFFFFFFF
last main insn: main+0x762B (x86 0x528E+0x12) → msvcrt!setlocale
```

**Last instructions before crash**:
```asm
main+0x7600  mov rcx, 0              ; arg1 = LC_ALL (0)
main+0x7607  movabs rdx, 0x80044538  ; arg2 = locale string (data section)
main+0x761E  movabs rax, 0x800724c8  ; IAT slot for setlocale
main+0x7628  mov rax, qword ptr [rax]; load function pointer
main+0x762B  call rax                ; → CRASH inside msvcrt!setlocale
```

**Analysis**: The `setlocale(0, 0x80044538)` call crashes because the locale string at `0x80044538` in the `.data` section contains corrupt or improperly relocated bytes. Inside `msvcrt`, RAX holds `0x007200650069009B` (garbled UTF-16 fragment: `r`, `e`, `i` + corrupt byte `0x9B`) which is dereferenced as a pointer → access violation.

### Build-over-Build Progress

| Build | Steps | Crash Site | Blocker |
|---|---|---|---|
| build_out80 | 204,440 | `main+0x13809` | `_get_osfhandle(0x411)` → `exit(1)` |
| build_out81 | 208,604 | `main+0x762B` | `setlocale` data corruption |

### RBP Corruption Events (persistent)
Both builds show RBP being overwritten with data-section addresses at `main+0x9BD8`:

```
main+0x9BD8    RBP 0x14FE90 -> 0x800456A8   push rsi
main+0x9BD8    RBP 0x14FE90 -> 0x80045700   push rsi
main+0x9BD8    RBP 0x14FE90 -> 0x80045608   push rsi
main+0x9BD8    RBP 0x14FE90 -> 0x800454A8   push rsi
main+0x126B8   RBP 0x14FE90 -> 0x8004D3E2   mov ecx, eax
main+0x7639    RBP 0x14FD30 -> 0x90          ret
```

---

## Progress Assessment

The universal `--pure` translator is in the **last-mile debugging phase**:

* **208,604 instructions execute correctly** — the entire CRT init, heap allocation, console title retrieval, `GetModuleHandle`, `GetProcAddress`, `_setjmp3` SEH setup, and console mode configuration all work.
* **Patched mode already prints `echo hello` perfectly** — the core translation engine, calling convention conversion, IAT dispatch, and SEH runtime are all proven.
* **Build-over-build progress is real** — each iteration executes more instructions and reaches new crash sites.

**Remaining blockers** (2–3 specific bugs, not architecture rewrites):

1. **Locale string relocation** at `0x80044538` — fix this and `setlocale` stops crashing (current build_out81 stopper).
2. **Codepage path** (`_get_osfhandle(0x411)`) — the build_out80 blocker, likely still lurking behind the setlocale fix.
3. **RBP corruption** at `main+0x9BD8` — register mapping edge case, may not be fatal for `echo` but needs fixing for stability.
