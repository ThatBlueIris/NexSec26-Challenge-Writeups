# Flagchecker

- **CTF:** NexSec CTF
- **Category:** Reverse Engineering
- **Artifacts:** `eboot.bin` (PS Vita title), `solve.py`
- **Flag:** `nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}`

---

## Overview

`eboot.bin` is a PlayStation Vita title — `param.json` names it **`Flag Checker VI`**
(`titleId: PPSA99026`, `contentId: IV0000-PPSA99026_00-FLAGCHECKER`). It is a raw
x86-64 ELF with **no section headers**, so the flag check isn't labeled. The title
takes a password and returns `1` on success. Solved with **symbolic execution**
(angr): model the input as a symbolic buffer, find the path that returns `1`, and
let the solver hand back the bytes.

---

## Step 1 — Handouts

```
$ sha256sum eboot.bin solve.py sce_sys/param.json
0a2a4b60f6811327be6b6b3de91c22fa07b862c2cf55be181a53c79a7aae8705  eboot.bin
72b17b0d672ad924565cfedbf02777448d0576d7803934e6704b130b1c59b7a5  solve.py
9ae8d44362816ca87214e9ecf27e194f754ab3c539d11e468cf88fdc51826c2d  sce_sys/param.json
```

---

## Step 2 — What is this binary?

```
$ file eboot.bin
eboot.bin: ELF 64-bit LSB x86-64, version 1 (FreeBSD)

$ readelf -h eboot.bin
  Type:                      OS Specific: (fe10)     # PS Vita (SCE) executable
  Machine:                   Advanced Micro Devices X86-64
  Entry point address:       0x471b
  Number of program headers: 9
  Number of section headers: 0                        # sectionless / stripped
```

No sections, no symbols. Disassembly has to start at the entry point and reach the
check routine by hand; everything lives at flat offsets in the file.

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
(dogbolt.org)** and read the **Binary Ninja / Hex-Rays** views. The interesting
routine sits at **`0x40f0`**: it takes the candidate buffer in `rdi` and a length
of `0x28` (40) in `rsi`, and returns its verdict in `RAX`. Success is `return 1`.
There is no anti-analysis — the check is a pure function of the input — so the
cleanest path is to let a symbolic executor do the work rather than transcribe the
comparisons by hand.

---

## Step 5 — Set up the environment

angr needed a clean virtualenv (Arch's system Python is externally managed):

```
$ pip install angr claripy
error: externally-managed-environment ... (PEP 668)
$ source ~/venv/bin/activate
(venv) $ pip install "pycparser==2.21"     # angr pins 2.21; Arch shipped 2.22
Successfully installed pycparser-2.21
(venv) $ python -c "import angr, claripy; print('angr OK')"
angr OK
```

(`Unicorn is not installed` warnings are benign — the pure-Python backend runs
fine.)

---

## Step 6 — First angr attempt: no path

`eboot.bin` is sectionless, so it is loaded as a **blob at base 0** and the checker
is entered with `call_state(FUNC_ADDR, ptr, 0x28)`. The first run explored to the
success return but found nothing:

```
$ python solve.py
Loading binary...
cle.backends.blob | No entry_point was specified for blob eboot.bin, assuming 0
Exploring paths...
...
Failed to find a path.
Active states: 0
Deadended states: 0
```

The exploration was looking for *a* return to the sentinel address without saying
what "success" means, so the solver never had a target worth keeping.

---

## Step 7 — Second attempt: contradictory constraints

Constrain the found state's return value and it gets further — but the constraint
was applied too late, after the state had already been pruned:

```
$ python solve.py
Setting up state...
Exploring paths...
...
Path found! Checking return value...
Path found, but it returned False. Constraints are contradictory.
```

---

## Step 8 — Constrain `RAX == 1` at find-time

The fix is to make the *find predicate itself* require `RAX == 1` (and then add
that constraint to the found state before `eval`), so the explorer only keeps
states that return success. Final `solve.py`:

```python
import angr, claripy

proj = angr.Project('./eboot.bin', auto_load_libs=False,
                    main_opts={'backend': 'blob', 'arch': 'amd64', 'base_addr': 0})

FUNC_ADDR = 0x40f0
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
(venv) [arif@archlinux flagchecker]$ python solve.py
Loading binary...
Setting up state...
Exploring paths to find the SUCCESS state...
... angr warnings ...
Success path found!

FOUND FLAG: nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
(venv) [arif@archlinux flagchecker]$
```

---

## Flag & Proof of Concept

```
nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

The angr log references the checker's own offsets (`0x4104` … `0x410d` in
`eboot.bin`), tying this run to `eboot.bin` and confirming the routine at
`0x40f0` is what was solved.

Reproduction:

```bash
cd "Reverse Engineering/Flagchecker/flagchecker"
sha256sum eboot.bin
python3 -m venv venv && . venv/bin/activate && pip install angr claripy
python solve.py     # -> FOUND FLAG: nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

---

## Evidence

- **Artifacts hashed** (Step 1); originals unchanged.
- **Dogbolt used** for the native view; the success path is a 40-byte symbolic
  buffer at `0x40000000` entered at `0x40f0`.
- **Recorded solve** in the VSCode integrated-terminal scrollback
  (`~/.config/Code/User/workspaceStorage/b44ae37651719ff996df95dc38f6eef5/state.vscdb`):
  the two failed runs (Step 6 `Failed to find a path.`, Step 7 `Constraints are
  contradictory.`) and the final `Success path found!` /
  `FOUND FLAG: nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}`.
- The angr warnings naming `eboot.bin (0x4104)` … `(0x410d)` are in the same
  transcript.

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
  find predicate* is what turns "a path exists" into "give me the exact bytes" —
  discovering that was the whole of Step 6 → Step 8.
