# Windows 2000 x86 to Native x64 Binary Translator & Debugging Suite

An advanced, multi-stage static and dynamic binary translation system designed to convert Windows 2000 SP4 (NT 5.0.2195) x86 PE32 binaries to native, XP x64/Win10 x64 compatible PE64 (x86-64) binaries. This enables running legacy x86 system applications natively on 64-bit systems.

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

## Recent Issues & Critical Fixes

### 1. 16-Bit / 8-Bit Load Width Widening
* **Problem**: 16-bit and 8-bit absolute load instructions (e.g., `mov ax, [abs]` and `mov al, [abs]`) were being widened to full 32-bit or 64-bit widths during translation. This corrupted the upper bits of registers.
* **Fix**: Restored strict width validation. 65 distinct absolute-load instructions have been corrected.

### 2. Reanchor Scan Bound Guard
* **Problem**: The reanchor pass, which resolves relocated absolute addresses (such as `movabs`), was over-scanning and clobbering the `movabs` instruction belonging to the next adjacent instruction. 
  * *Example*: A `push`/`store` instruction reanchor clobbered a neighboring `cmp [0x1cf64]` (at RVA `0xC67E` in `cmd.exe`), corrupting it into `cmp [0x1fb00]`. Since `0x1fb00` is the `jmp_buf` address, the value read was always non-zero, forcing `cmd` to immediately exit via a false `exit(1)` error path before ever running subcommands.
* **Fix**: Implemented a block-boundary guard in `_scan_hi`. The scan is capped at the start of the next translated block.
  * A true `movabs` instruction block spans $\ge 12$ bytes (with a 10-byte instruction payload). 
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

The behavior differs between the translation modes in build `build_out81`:

* **With Patch Mode Enabled (`cmd_shim.exe`)**:
  * Tracing `cmd /c echo hello` confirms that the absolute load address `[0x1cf64]` is now read correctly, the false error exit path is gone, and **`hello` successfully prints** to standard output.

* **Universal `--pure` Mode (`cmd_pure.exe`)**:
  * This mode is currently under the active reversing/reverse-engineering stage.
  * In `build_out80`, the tracer successfully executed **204,440 instructions** (steps) in pure mode before hitting exceptions (such as stack/register state issues like RBP corruption).
  * In `build_out81`, despite the latest fixes, **`cmd_pure.exe` still does not print `echo`** in pure mode, and active investigation is ongoing to resolve remaining blockages.
