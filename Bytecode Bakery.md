# Bytecode Bakery

- **CTF:** NexSec CTF
- **Category:** Reverse Engineering
- **Artifacts:** `recipe.bin`, `oven.py`, `disasm.py`, `solve.py`, `asd`
- **Flag:** `nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}`

---

## Overview

`oven.py` "bakes" a bytecode *recipe* (`recipe.bin`) using a line of *ingredients*
the player types in. If the recipe accepts the ingredients, that string is the
flag. The recipe is a small **custom stack VM** (14 opcodes), not native code — so
the entire check is recoverable from the bytecode. (Dogbolt is for native PE/ELF;
for a custom VM the right "decompiler" is the provided `disasm.py` plus `oven.py`'s
dispatcher.)

---

## Step 1 — Handouts

```
$ sha256sum recipe.bin oven.py disasm.py solve.py asd
ee84b6f469eb82dac886786e28e65e8ea1a3a3436d2778a0e1a54b4b467db4a0  recipe.bin
5c6bc7847299daf7be8d5cfb95a933ac5327824968f894997256bc28aea8b592  oven.py
e9b24f2c9e2a7e4002fdee8d2f9b5c43a3ac1503365d5ac98125ce97c353890c  disasm.py
9aa04aafad2f115935aff6d5dcd820058d1289c29a983392e1a96c538be6099f  solve.py
efd6a4835480390a745b881e9cb970fd80c2122a3deec1a05bced8e7705d3ceb  asd
```

Recipe header (`struct.unpack("<4sBBH", blob[:8])`):

```
magic     = b'BAKE'
version   = 1
input_len = 50        # exactly 50 ingredients
code_len  = 1143
```

---

## Step 2 — Read the host (`oven.py`)

`oven.py` is a stack machine. The dispatcher gives the full opcode table:

| Opcode | Mnemonic | Effect |
|---|---|---|
| `0x01` | `PUSH imm8` | push the next byte |
| `0x02` | `LOAD idx` | push `ingredients[idx]` |
| `0x03` | `ADD` | `(a + b) & 0xFF` |
| `0x04` | `SUB` | `(a - b) & 0xFF` |
| `0x05` | `XOR` | `a ^ b` |
| `0x06` | `ROL` | rotate `v` left by `n & 7` |
| `0x07` | `EQ` | push `1` if `a == b` else `0` |
| `0x08` | `JNZ u16` | pop; jump to target if non-zero |
| `0x09` | `JMP u16` | unconditional jump |
| `0x0A` | `REJECT` | return `False` |
| `0x0B` | `ACCEPT` | return `True` |
| `0x0C` | `DUP` | duplicate top of stack |
| `0x0D` | `AND` | `a & b` |

---

## Step 3 — Disassemble the recipe

Ran the provided `disasm.py` (a 40-line lifter over the opcode table):

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

The very first instruction is `JMP 0x00ec`. That single jump splits the program in
two.

---

## Step 4 — Spot the two blocks

1. **Dead block, `0x0003`–`0x00eb`.** The entry point jumps straight to `0x00ec`,
   so this block *never runs*. It holds 25 checks of the form
   `input[i] ^ k == v`, ANDed together, ending in `DUP; JNZ; REJECT; ACCEPT`.

2. **Live chain, `0x00ec`–`0x0475`.** This is the real check. It opens with
   `PUSH 0x01` (the seed for the `AND` accumulator) and then runs dependent
   per-byte checks.

---

## Step 5 — Recover the decoy flag

Inverting each pair in the dead block (`i = k ^ v`) yields a plausible-looking but
**wrong** flag:

```
nexsec26{n0t_th15_r3c1p3}
```

A player who disassembles and inverts the first block they read will submit this
losing decoy.

---

## Step 6 — Understand the live chain

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
the chain ends in `DUP; JNZ 0x0476; REJECT; ACCEPT` — accepted only if every check
passed.

Because the checks run in input order and are `AND`ed, **the number of `EQ`s that
have passed is an oracle for how many leading bytes are correct.**

---

## Step 7 — Write a tracing solver (`solve.py`)

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
including the chained `ROL`/`SUB`/`ADD` relations. (An earlier scratch script,
`asd`, monkey-patched `oven.bake` to print a stack snapshot at `0x07`/`0x08` — the
dynamic counterpart to this static oracle.)

---

## Step 8 — Run it

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

---

## Flag & Proof of Concept

```
nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}
```

The flag is **50 bytes**, matching `input_len = 50`. The trailing `_ZXJ6eQ==` is
base64 for `er6y` (`nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_er6y}`) — flavour
text, not a second stage.

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
  `nexsec26{n0t_th15_r3c1p3}`.
- **Live chain** independently disassembled; byte 0 inverts to `'n'` by hand
  (`rol8(0x6e^0xaa^0x8b,7) - 0xdd = 0xca`), confirming the solver's first output.

---

## Remediation / Key Takeaways

- **Root cause:** the accepted input is stored as plaintext constants inside
  player-visible bytecode. Any check that materialises the secret as data can be
  recovered.
- **Fix:** don't ship the answer. Compare a *salted hash* of the input
  (`SHA-256(salt ‖ input)` vs. an embedded digest) so the pre-image can't be read
  out of the code. For a toy VM, remove or clearly gate dead code — the decoy
  block is a speed bump, not a control.
- **Lesson:** for a data-driven checker, look at **control flow first**. Here
  `JMP 0x00ec` at entry identifies the live chain; the `EQ`-pass count then turns
  the whole thing into a trivial byte-by-byte brute force.
