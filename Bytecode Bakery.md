# Bytecode Bakery

- **CTF:** NexSec CTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Artifacts:** `recipe.bin`, `oven.py`, `disasm.py`, `solve.py`, `asd`
- **Objective:** Recover the ingredient string accepted by a custom bytecode checker.
- **Flag:** `nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}`

---

## Overview

`oven.py` "bakes" a bytecode *recipe* (`recipe.bin`) using a line of *ingredients*
the player types in. If the recipe accepts the ingredients, that string is the
flag.

`recipe.bin` is **not** native machine code. It is a custom stack VM program
interpreted by `oven.py` (14 opcodes). Feeding it to a native decompiler
(Dogbolt/Ghidra/objdump) produces garbage such as `0xd079c01`, `ROLB`,
`__bound_gprv_mema32` — plausible-looking but meaningless. The right target is the
**interpreter**: read `oven.py` to learn the ISA, then disassemble `recipe.bin`
with that ISA.

The recipe is adversarial-by-design: the entry point `JMP`s over a 25-check
**decoy block** that yields a believable but wrong flag, and the real check lives
in the live chain after the jump.

---

## Initial Recon & Enumeration

### Step 1 — Handouts

```
$ sha256sum recipe.bin oven.py disasm.py solve.py asd
ee84b6f469eb82dac886786e28e65e8ea1a3a3436d2778a0e1a54b4b467db4a0  recipe.bin
5c6bc7847299daf7be8d5cfb95a933ac5327824968f894997256bc28aea8b592  oven.py
e9b24f2c9e2a7e4002fdee8d2f9b5c43a3ac1503365d5ac98125ce97c353890c  disasm.py
9aa04aafad2f115935aff6d5dcd820058d1289c29a983392e1a96c538be6099f  solve.py
efd6a4835480390a745b881e9cb970fd80c2122a3deec1a05bced8e7705d3ceb  asd
```

### Step 2 — File format

```python
MAGIC = b"BAKE"
...
version, input_len, code_len = struct.unpack("<BBH", blob[4:8])
code = blob[8:8 + code_len]
```

Header layout (`struct.unpack("<4sBBH", blob[:8])`):

```
magic     = b'BAKE'
version   = 1
input_len = 50        # exactly 50 ingredients
code_len  = 1143
```

Input handling:

```python
ingredients = text.strip().encode("latin-1", "replace")
if len(ingredients) != input_len:
    print(f"The recipe needs exactly {input_len} ingredients.")
```

The flag must be exactly `input_len` bytes, read from stdin and latin-1 encoded.

---

## Vulnerability Analysis

The accepted input is materialised as **plaintext constants inside player-visible
bytecode**. The live chain computes, per index, a transform of the input and
compares it against an immediate (`EQ`), so each byte is recoverable without any
key or binary exploitation:

- **Root cause:** the secret is *data in the program*, not a one-way function of it.
  A disassembler plus a byte-at-a-time oracle recovers the whole input.
- **The oracle:** checks run in input order and are `AND`ed. The number of `EQ`
  opcodes that pass before the first failure equals how many leading bytes are
  correct — a monotonic prefix oracle.
- **`interpreter + data == program`:** with a custom VM, re-implementing the VM in
  ~30 lines of Python is faster and safer than hand-reversing optimized bytecode.

---

## Exploitation

### Step 3 — Read the host (`oven.py`)

`oven.py` is a stack machine. The dispatcher gives the full opcode table:

| Opcode | Mnemonic | Effect | Operand bytes |
|---|---|---|---|
| `0x01` | `PUSH imm8` | push the next byte | 1 |
| `0x02` | `LOAD idx` | push `ingredients[idx]` | 1 |
| `0x03` | `ADD` | `(a + b) & 0xFF` | 0 |
| `0x04` | `SUB` | `(a - b) & 0xFF` | 0 |
| `0x05` | `XOR` | `a ^ b` | 0 |
| `0x06` | `ROL` | rotate `v` left by `n & 7` | 0 |
| `0x07` | `EQ` | push `1` if `a == b` else `0` | 0 |
| `0x08` | `JNZ u16` | pop; jump to target if non-zero | 2 |
| `0x09` | `JMP u16` | unconditional jump | 2 |
| `0x0A` | `REJECT` | return `False` | 0 |
| `0x0B` | `ACCEPT` | return `True` | 0 |
| `0x0C` | `DUP` | duplicate top of stack | 0 |
| `0x0D` | `AND` | `a & b` | 0 |

VM state: a byte-valued stack, program counter `pc`, and `ingredients` (the input
array). Execution is capped at `MAX_STEPS = 100_000`. `bake()` returns `True` only
on `ACCEPT` (`0x0B`), `False` on `REJECT` (`0x0A`) or running off the end.

### Step 4 — Disassemble the recipe

Ran the provided `disasm.py` (a small lifter over the opcode table):

```
$ python3 disasm.py | head
version=1 input_len=50 code_len=1143
0000: JMP    0x00ec
0003: PUSH   0x01
0005: LOAD   0x00
0007: PUSH   0xf2
0009: XOR
000a: PUSH   0x9c
000c: EQ
000d: AND
...
```

The very first instruction is `JMP 0x00ec`, splitting the program in two.

### Step 5 — Spot the two blocks

1. **Dead block, `0x0003`–`0x00eb`.** The entry point jumps straight to `0x00ec`,
   so this block **never runs**. It holds **25** checks of the form
   `input[i] ^ k == v`, `AND`ed together.
2. **Live chain, `0x00ec`–`0x0475`.** The real check. It opens with `PUSH 0x01`
   (the seed for the `AND` accumulator), then runs dependent per-byte checks.

### Step 6 — The decoy (do not submit it)

Inverting each pair in the dead block (`i = k ^ v`) yields a plausible-looking but
**wrong** 25-byte flag:

```
nexsec26{n0t_th15_r3c1p3}
```

A player who disassembles and inverts the first block they read submits this losing
decoy. Note it is **25 bytes**, so `oven.py` rejects it on length before it is even
evaluated:

```
$ printf 'nexsec26{n0t_th15_r3c1p3}' | python3 oven.py
Enter ingredient list: The recipe needs exactly 50 ingredients.
```

It is a pure decoy value computed by dead code — not a submittable answer.

### Step 7 — Understand the live chain

The live chain starts at `0x00ec`:

```
00ec: PUSH   0x01          ; accumulator seed
00ee: LOAD   0x00          ; input[0]
00f0: PUSH   0xaa ; XOR
00f3: PUSH   0x8b ; XOR
00f6: PUSH   0x07 ; ROL
00f9: PUSH   0xdd ; SUB
00fc: PUSH   0xca ; EQ
00ff: AND
```

i.e. byte 0 satisfies `rol8(input[0] ^ 0xaa ^ 0x8b, 7) - 0xdd == 0xca`
(→ `input[0] = 0x6e = 'n'`).

Every later check **chains off the previous byte**:

```
LOAD i; LOAD (i-1); XOR
PUSH k; XOR
PUSH n; ROL
PUSH m; SUB|ADD
PUSH v; EQ
AND
```

i.e. `rol8(input[i] ^ input[i-1] ^ k, n) ± m == v`. All results are `AND`ed, and
the chain ends with `DUP; JNZ <fail>; REJECT; ACCEPT` — accepted only if every
check passed. Because the checks run in input order and are `AND`ed, **the number
of `EQ`s that have passed is an oracle for how many leading bytes are correct.**

### Step 8 — Tracing solver (`solve.py`)

`solve.py` re-implements the VM as a *tracing interpreter*: it returns `False` on
the first failing `EQ`, otherwise reports the count of `EQ`s passed. It then walks
the input byte by byte, trying all 256 values and keeping the one that pushes the
pass count to `i + 1`:

```python
for i in range(ilen):
    cracked = False
    for c in range(256):
        flag[i] = c
        ok, depth = trace_depth(bytes(flag))
        if ok:
            print("\n[+] FULL FLAG:", bytes(flag)); cracked = True; break
        if depth >= i + 1:      # passed the check for byte i
            print(f"  byte {i:2d} = {c:02x} ({chr(c)!r})")
            cracked = True; break
```

No algebra needs re-deriving — the `EQ`-pass count alone identifies each byte,
including the chained `ROL`/`SUB`/`ADD` relations. (`asd` is an abandoned earlier
attempt: a stub that monkey-patches `oven.bake` to print a stack snapshot at
`0x07`/`0x08`, but never completed — the static `EQ`-count oracle above superseded
it.)

### Step 9 — Run it

```
$ python3 solve.py
input_len = 50
  byte  0 = 6e ('n')
  byte  1 = 65 ('e')
  byte  2 = 78 ('x')
  byte  3 = 73 ('s')
  byte  4 = 65 ('e')
  byte  5 = 63 ('c')
  byte  6 = 32 ('2')
  byte  7 = 36 ('6')
  byte  8 = 7b ('{')
  byte  9 = 74 ('t')
  ...
  byte 46 = 51 ('Q')
  byte 47 = 3d ('=')
  byte 48 = 3d ('=')

[+] FULL FLAG: b'nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}'

[+] DONE: b'nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}'
```

Runtime: ~2 s (≤ 12,800 VM executions of ≤ 100k steps each).

---

## Flag & Proof of Concept

```
nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}
```

Verify directly against the recipe — no side effects, no scoreboard risk:

```bash
$ printf 'nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}' | python3 oven.py
Enter ingredient list: Fresh from the oven! Submit your ingredient list as the flag.
```

The VM accepted every comparison byte-for-byte, including both trailing `=`.

**On the trailing `==`:**

```
$ echo 'ZXJ6eQ==' | base64 -d
erzy
```

`ZXJ6eQ==` is standard base64 for `erzy` — the challenge author's handle. It is
**flavour text baked into the flag**, not a second stage. The `==` is two bytes of
base64 padding and is *part of the flag*: the bytecode literally compares
`input[47]` and `input[48]` against `0x3D` (`=`), so stripping the padding would
fail the final two `EQ` checks and also produce invalid base64.

Length sanity check: `len("nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}") == 50`,
matching `input_len = 50`. ✔

Reproduction:

```bash
cd "Reverse Engineering/Bytecode Bakery"
sha256sum recipe.bin          # ee84b6f4...467db4a0
python3 disasm.py | head      # inspect the VM
python3 solve.py              # -> FULL FLAG: nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}
```

---

## Evidence

- **Artifacts hashed** (Step 1). The solver runs purely from `recipe.bin` — no
  network, no guessing.
- **Recipe header** verified: `BAKE`, v1, `input_len=50`, `code_len=1143`.
- **Decoy flag** recovered by decoding the unreachable block at `0x0003`:
  `nexsec26{n0t_th15_r3c1p3}` (25 checks, indices 0–24).
- **Live chain** independently disassembled; byte 0 inverts to `'n'` by hand
  (`rol8(0x6e ^ 0xaa ^ 0x8b, 7) - 0xdd == 0xca`), confirming the solver's first output.
- **Base64 payload** `ZXJ6eQ==` decodes to `erzy`.

---

## Remediation / Key Takeaways

- **Root cause:** the accepted input is stored as plaintext constants inside
  player-visible bytecode. Any check that materialises the secret as data can be
  recovered.
- **Fix:** don't ship the answer. Compare a *salted hash* of the input
  (`SHA-256(salt ‖ input)` vs. an embedded digest) so the pre-image can't be read
  out of the code. For a toy VM, remove or clearly gate dead code — the decoy block
  is a speed bump, not a control.
- **Lesson:** for a data-driven checker, look at **control flow first**. Here
  `JMP 0x00ec` at entry identifies the live chain; the `EQ`-pass count then turns
  the whole thing into a trivial byte-by-byte brute force. Also: match the tool to
  the format — a custom bytecode file is not a native binary, and its interpreter is
  the map.
