# Flagchecker

- **CTF:** NexSec CTF
- **Category:** Reverse Engineering
- **Artifacts:** `eboot.bin` (PS5 title), `solve.py`
- **Flag:** `nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}`

---

## Overview

`eboot.bin` is a PlayStation 5 title — `param.json` names it **`Flag Checker VI`**
(`titleId: PPSA99026`, `contentId: IV0000-PPSA99026_00-FLAGCHECKER`). It is a raw
x86-64 ELF with **no section headers**, so the flag check isn't labeled. The title
takes a password and returns `1` on success. Solved with **symbolic execution**
(angr): model the input as a symbolic buffer, find the path that returns `1`, and
let the solver hand back the bytes.

---

## Step 1 — Handouts

```
$ sha256sum eboot.bin solve.py sce_sys/param.json app0/sce_sys/param.json
0a2a4b60f6811327be6b6b3de91c22fa07b862c2cf55be181a53c79a7aae8705  eboot.bin
72b17b0d672ad924565cfedbf02777448d0576d7803934e6704b130b1c59b7a5  solve.py
9ae8d44362816ca87214e9ecf27e194f754ab3c539d11e468cf88fdc51826c2d  sce_sys/param.json
9ae8d44362816ca87214e9ecf27e194f754ab3c539d11e468cf88fdc51826c2d  app0/sce_sys/param.json
```

---

## Step 2 — What is this binary?

```
$ file eboot.bin
eboot.bin: ELF 64-bit LSB x86-64, version 1 (FreeBSD)

$ readelf -h eboot.bin
  Type:                      OS Specific: (fe10)     # SCE executable
  Machine:                   Advanced Micro Devices X86-64
  Entry point address:       0x471b
  Number of program headers: 9
  Number of section headers: 0                        # sectionless / stripped
```

No sections, no symbols. The program headers matter because they explain the two
address spaces used later:

```
$ readelf -l eboot.bin
  LOAD  Offset 0x0000...4000  VirtAddr 0x0000...0000  R E
  LOAD  Offset 0x0000...c000  VirtAddr 0x0000...8000  RW
  LOAD  Offset 0x0000...14000 VirtAddr 0x0000...10000 R
```

The first `LOAD` maps **file offset `0x4000` → vaddr `0`**. Keep that in mind.

---

## Step 3 — `param.json`

```json
{
  "titleId": "PPSA99026",
  "contentId": "IV0000-PPSA99026_00-FLAGCHECKER",
  "localizedParameters": { "en-US": { "titleName": "Flag Checker VI" } }
}
```

The title is a password gate that returns `1` on the correct input.

---

## Step 4 — Decompile with Dogbolt

It is a native x86-64 ELF, so I dropped `eboot.bin` into **Dogbolt
(dogbolt.org)**. Because the binary is stripped and sectionless, Dogbolt honors
the ELF program headers to place the segments. I read the **Ghidra** view: the
check routine appears at virtual address **`0xf0`**, labeled `FUN_000000f0`.
(Binary Ninja calls the same function `sub_f0`; Hex-Rays does not produce usable
pseudocode for it.)

```asm
; file offset 0x40f0 == ELF vaddr 0xf0
    40f0: 31 c0              xor    eax,eax
    40f2: 48 85 ff           test   rdi,rdi
    40f5: 0f 84 c8 08 00 00  je     0x49c3
    40fb: 83 fe 28           cmp    esi,0x28         ; length must be 0x28 (40)
    40fe: 0f 85 bf 08 00 00  jne    0x49c3
    4104: 55                 push   rbp
    4105: 41 57              push   r15
    4107: 41 56              push   r14
```

The routine takes the candidate buffer in `rdi` and a length of `0x28` (40) in
`rsi`, and returns its verdict in `RAX` (`return 1` on success).

**How to land on it.** Do not text-search the page for `0xf0` — that matches
unrelated constants such as `& 0xf0000` inside other functions (for example the
table-building loop at vaddr `0xc30`). Use *Go To Address / Offset* `0xf0`, or
search the listing for the length gate `cmp esi,0x28`.

> **Address note — why the solver says `0x40f0`, not `0xf0`.** The first `LOAD`
> segment maps **file offset `0x4000` → vaddr `0`**, so the routine at Ghidra
> vaddr **`0xf0`** lives at **file offset `0x40f0`**. The angr script loads
> `eboot.bin` as a raw **blob at base `0`**, where an address *is* a file offset —
> so the same function is entered at **`0x40f0`** there. Same bytes, two address
> spaces. There is no `sub_40f0`: what Dogbolt shows at `0x40f0` (file `0x80f0`)
> is unrelated code.

---

## Step 5 — The decrypted strings are decoys (LCG)

The binary hides its strings behind a small LCG-based XOR loop. Ghidra shows one
of them at `FUN_00002470` (vaddr `0x2470`, file `0x6470`). The disassembly is the
whole algorithm:

```asm
; FUN_00002470 == file 0x6470
mov    eax,0x20261014          ; seed
xor    ecx,ecx
lea    rdx,[rip+0xdb9a]        # 0x14018   (DAT_00010018, ciphertext)
lea    rsi,[rip+0x5d2b]        # 0xc1b0    (DAT_000081b0, output)
.loop:
imul   eax,eax,0x1fb9
movzx  r8d,BYTE PTR [rcx+rdx*1]
add    eax,0x6efb
imul   rdi,rax,0x3e63a567 ; shr rdi,0x2f ; imul edi,edi,0x20d38 ; sub eax,edi  ; % 0x20d38
xor    r8b,al
mov    BYTE PTR [rcx+rsi*1],r8b
inc    rcx
cmp    rcx,0x26                ; 38 bytes
jne    .loop
```

Emulating it (remembering the 32-bit overflow and the `% 0x20d38` step):

```python
data = open('eboot.bin','rb').read()
ct = data[0x14018:0x14018+0x26]
u = 0x20261014
out = bytearray()
for b in ct:
    u = (u * 0x1fb9 + 0x6efb) & 0xFFFFFFFF
    u = u % 0x20d38
    out.append(b ^ (u & 0xff))
print(repr(bytes(out)))
```

Output:

```
b'ACHIEVEMENT: Congratulations.... GG!\n\x00'
```

That is only a trophy/achievement message — **not** the flag. The flag is the
password itself, enforced by the routine at `0xf0`. The string work was a dead
end, so the next step was to attack the comparison chain directly.

---

## Step 6 — Attempt 1: manual Z3 transcription

`FUN_000000f0` is one long chain of 40-byte bitwise constraints — around **66**
relations. The first attempt was to transcribe them into `z3-solver`. Each
operation had to be widened, because C promotes the 8-bit bytes to 32-bit before
the arithmetic, so every operand is wrapped in `ZeroExt`:

```python
from z3 import *

p = [BitVec(f'p{i}', 8) for i in range(0x28)]
s = Solver()
for i in range(0x28):
    s.add(p[i] >= 0x20, p[i] <= 0x7e)      # printable ASCII

# example relation: ((p[0x14] + p[6]) | p[0x17]) ^ p[0x14] == 0xae
s.add(((ZeroExt(1, p[0x14]) + ZeroExt(1, p[6]))
       | ZeroExt(1, p[0x17])) ^ ZeroExt(1, p[0x14]) == 0xae)
# ... 65 more ...
```

This grew to a ~6 KB script across several revisions. The problem is structural:
one wrong byte offset, one missed `ZeroExt`, or one operator-precedence slip
poisons the whole system, and the model reports unsatisfiable with no pointer to
the bad line. Bisecting 66 equations by hand was slower than switching tools, so
I dropped the static route.

---

## Step 7 — Attempt 2: angr with `blank_state`

Because `eboot.bin` is sectionless, it loads as a raw **blob at base 0**, so
addresses are file offsets (`0x40f0`). The first dynamic attempt started mid-air:

```python
state = proj.factory.blank_state(addr=0x40f0)
state.regs.rdi = BUF
state.regs.rsi = 0x28
state.regs.rsp = STACK
state.memory.store(STACK, claripy.BVV(0xdeadbeef, 64))
```

This fails because there is no stack frame. When the prologue pushes callee-saved
registers, angr has nothing to push:

```
WARNING | Filling register rbp with 8 unconstrained bytes referenced from 0x4104 ...
WARNING | Filling register r15 with 8 unconstrained bytes referenced from 0x4105 ...
...
Failed to find a path.
Active states: 0
Deadended states: 0
```

The pushes and pops of `rbp`, `r15`–`r12`, `rbx` are now symbolic garbage, and
the return cannot be resolved.

---

## Step 8 — `call_state`: correct stack, wrong path

Using `call_state` gives angr a proper frame and a fake return address:

```python
state = proj.factory.call_state(FUNC_ADDR, claripy.BVS('password_ptr', 64), 0x28,
                                ret_addr=0xdeadbeef)
```

Exploration now reaches the return, but it finds the first path to `ret`, which
is the *failure* path — the function is a giant `if` with two exits:

```
Path found! Checking return value...
Path found, but it returned False. Constraints are contradictory.
```

Checking `RAX` **after** `explore()` is too late: the state that satisfied the
`find` predicate is the `RAX = 0` exit, and constraining it to `1` contradicts it.

---

## Step 9 — Constrain `RAX == 1` inside the find predicate

The fix is to make success part of the search condition, so the explorer only
keeps states that both reach the sentinel and can return `1`. Final `solve.py`:

```python
import angr, claripy

proj = angr.Project('./eboot.bin', auto_load_libs=False,
                    main_opts={'backend': 'blob', 'arch': 'amd64', 'base_addr': 0})

FUNC_ADDR = 0x40f0   # = ELF vaddr 0xf0; blob base is 0, so address == file offset
RET_ADDR  = 0xdeadbeef

state = proj.factory.call_state(FUNC_ADDR, claripy.BVS('password_ptr', 64), 0x28,
                                ret_addr=RET_ADDR)

password  = claripy.BVS('password', 40 * 8)      # 40 symbolic bytes
BUF_ADDR  = 0x40000000
state.memory.store(BUF_ADDR, password)
state.regs.rdi = BUF_ADDR                        # param_1 -> password buffer

def is_successful_ret(s):
    return s.addr == RET_ADDR and \
           s.solver.satisfiable(extra_constraints=[s.regs.rax == 1])

simgr = proj.factory.simgr(state)
simgr.explore(find=is_successful_ret)

found = simgr.found[0]
found.solver.add(found.regs.rax == 1)
print("FOUND FLAG:", found.solver.eval(password, cast_to=bytes).decode('ascii', 'replace'))
```

Run:

```
$ python solve.py
Loading binary...
Setting up state...
Exploring paths to find the SUCCESS state...
... angr warnings ...
Success path found!

FOUND FLAG: nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

---

## Flag & Proof of Concept

```
nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

The angr log references the checker's own offsets (`0x4104` … `0x410d` in
`eboot.bin`). Those are blob (file-offset) addresses — the `push rbp` … `push rbx`
prologue shown in Step 4 (vaddr `0x104` … `0x10d`), i.e. the body of the routine
entered at blob `0x40f0` / vaddr `0xf0`.

Reproduction:

```bash
cd "Reverse Engineering/Flagchecker/flagchecker"
sha256sum eboot.bin
python3 -m venv venv && . venv/bin/activate
pip install angr claripy
pip install "pycparser==2.21"     # angr on Python 3.14 needs 2.21; Arch shipped 2.22
python solve.py                   # -> FOUND FLAG: nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

---

## Evidence

- **Artifacts hashed** (Step 1); originals unchanged.
- **Dogbolt used** for the native view — the `eboot.bin` session id from the
  browser history is `b8630639-c78b-4347-aac0-93ec46050eba`, opened on the
  **Ghidra** pane (`#Ghidra=…`), which is where `FUN_000000f0` comes from.
- **String decrypt reproduced from the artifact** (Step 5): the exact 38-byte
  ciphertext at file `0x14018` decrypts to `ACHIEVEMENT: Congratulations.... GG!`.
- **Environment**: Python **3.14.8** in the recorded session; `pycparser` was
  downgraded from **2.22 → 2.21** for angr.
- **Recorded solve** in the VSCode integrated-terminal scrollback
  (`~/.config/Code/User/workspaceStorage/b44ae37651719ff996df95dc38f6eef5/state.vscdb`):
  the blank-state failure (`Failed to find a path.`, `Active states: 0`), the
  contradictory-constraints run, and the final `Success path found!` /
  `FOUND FLAG: nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}`.
- **Iteration trail**: 18 saved revisions of `solve.py` in
  `~/.config/Code/User/History/31d85888/` — six `blank_state` attempts, nine
  Z3 transcriptions (66 `s.add` each), then the `call_state` script that is
  byte-identical to the final `solve.py`.

---

## Remediation / Key Takeaways

- **Root cause:** a password check implemented as a deterministic function with a
  single success return. Any such function is a symbolic-execution target.
- **Fix:** don't validate secrets with plain comparisons; use a MAC/signature
  check (`verify(key, msg)`) so recovering the accepted input requires the key,
  and add cost against automated exploration (state explosion, rate/time gates).
- **Lesson:** for sectionless console/embedded binaries, load as a blob at the
  entry point, find the check routine, and let angr solve for the input where the
  success flag is set. Constraining the **return value** (`RAX == 1`) *inside the
  find predicate* is what turns "a path exists" into "give me the exact bytes."
- **Address bookkeeping:** decompilers use ELF vaddrs (`0xf0`); a base-0 blob
  loader uses file offsets (`0x40f0`). The `0x4000` segment gap is the whole
  difference — and the same trap applies to the search box: go to the *address*,
  don't text-search `0xf0`.
- **Static vs dynamic:** hand-transcribing optimized C bitwise math into Z3 is
  error-prone (8-bit vs 32-bit promotion, operator precedence, one typo = unsat).
  Symbolic execution bypasses understanding the math entirely.
