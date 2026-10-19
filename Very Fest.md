# Very Fest

- **CTF:** NexSec CTF
- **Category:** Misc (EVM / smart-contract bytecode)
- **Artifacts:** `VeryFest.evm` (hex-encoded EVM runtime bytecode), `README.md`
- **Flag:** `nexsec26{decentralization_means_giving_up_dominance_over_security}`

---

## Overview

`README.md` is one line — *"Bytecode analysis made easy (re.hanz.dev)"* — pointing
straight at the EVM disassembler `re.hanz.dev`. `VeryFest.evm` is a hex string: the
raw **runtime bytecode** of an Ethereum contract. No ABI, no source. The job is to
disassemble it, find the flag path, and recover the constants it compares against.
(Dogbolt is for native PE/ELF; for EVM bytecode the right tool is an EVM
disassembler.)

---

## Step 1 — Handouts

```
$ sha256sum VeryFest.evm README.md
32adaebf527aa79fea6bb81c1156ec633eb9d63806cfd823146fc315e60a0f83  VeryFest.evm
fb1368bde1f2107d38488b27c2e9d1c287af5d9bbd47e66075da9332300f80e6  README.md
```

The `.evm` file is pure hex; decoding it gives bytecode that opens with the
standard Solidity dispatcher.

---

## Step 2 — Decode the hex

```python
b = bytes.fromhex(open("VeryFest.evm").read().strip())
# b[0:4] = 36 60 04 90 ...  -> CALLDATASIZE PUSH1 0x04 SWAP1 ...
```

---

## Step 3 — Disassemble in `re.hanz.dev`

Pasting the bytecode into `re.hanz.dev` shows the function selector dispatcher:

```
CALLDATASIZE PUSH1 0x04 SWAP1 LT PUSH1 0x34 JUMPI   ; revert if calldata < 4 bytes
PUSH0 CALLDATALOAD PUSH1 0xe0 SHR                    ; selector = calldata[0:4]
PUSH4 0x146e61ed DUP2 EQ PUSH1 0x2e JUMPI            ; -> 0x2e
PUSH4 0x799320bb DUP2 EQ PUSH1 0x43 JUMPI            ; -> 0x43
PUSH4 0xd99a8dc3 DUP2 EQ PUSH1 0x52 JUMPI            ; -> 0x52
PUSH1 0x34 JUMP                                       ; else revert
```

Three external functions:

| Selector | Body | Role |
|---|---|---|
| `0x146e61ed` | `PUSH0 SLOAD PUSH1 0xc0 MSTORE PUSH1 0x20 PUSH1 0xc0 RETURN` | **getter** — returns `storage[0]` (the stored flag) |
| `0x799320bb` | `CALLVALUE` + `SLOAD[1]` guard, jump `0x249` | guard / read path |
| `0xd99a8dc3` | reads calldata, compares, stores + logs | **setter / checker** |

---

## Step 4 — Read the checker

The setter (`0xd99a8dc3`) is the important one. It reads the supplied calldata in
32-byte words and compares each word against an **embedded constant** using `EQ`
(`0x14`). If everything matches it stores the value and emits a `LOG3` with topic:

```
0x6747c18256028de8cd2fa276e75d6b4193ac34c1b55fa8e71797ac132d32ad39
```

The expected value is written as literal `PUSH32` operands:

```
PUSH32 <word0> ... EQ ...
PUSH32 <word1> ... EQ ...
PUSH2  0x797d  PUSH1 0xf0 SHL ... EQ ...   ; "y}" packed into the high bytes
```

That is the whole bug: because the bytecode is public, so is the "secret".

---

## Step 5 — Lift every `PUSH*` operand

Walk the bytecode and pull the operand of each `PUSH1..PUSH32` (`0x60..0x7f`),
keeping the printable ones:

```python
b = bytes.fromhex(open("VeryFest.evm").read().strip())
i, chunks = 0, []
while i < len(b):
    op = b[i]
    if 0x60 <= op <= 0x7f:                 # PUSH1 .. PUSH32
        n = op - 0x5f
        data = b[i+1:i+1+n]
        if any(32 <= c < 127 for c in data):
            chunks.append((i, data))
        i += 1 + n
    else:
        i += 1
for off, d in chunks:
    print(hex(off), d.hex(), repr(d.decode("latin-1")))
```

Result:

```
0x116  6e657873656332367b646563656e7472616c697a6174696f6e5f6d65616e735f  'nexsec26{decentralization_means_'
0x14a  676976696e675f75705f646f6d696e616e63655f6f7665725f73656375726974  'giving_up_dominance_over_securit'
0x17e  797d                                                              'y}'
```

---

## Step 6 — Concatenate

The three words are 32 + 32 + 2 bytes; concatenated they are the flag (the short
tail is the `PUSH2 0x797d` shifted left by `0xf0`, i.e. `"y}"` in the high bytes):

```
nexsec26{decentralization_means_giving_up_dominance_over_security}
```

The three phrases — *decentralization*, *means*, *giving up dominance over
security* — read as the intended message, confirming the reconstruction.

---

## Flag & Proof of Concept

```
nexsec26{decentralization_means_giving_up_dominance_over_security}
```

Reproduction:

```bash
cd "Misc/Very Fest"
sha256sum VeryFest.evm        # 32adaebf...5e60a0f83
python3 -c 'b=bytes.fromhex(open("VeryFest.evm").read().strip()); \
print([b[i+1:i+1+(b[i]-0x5f)].decode() for i in range(len(b)) if 0x7f==b[i]])'
```

---

## Evidence

- **Artifact hashed** (Step 1); original unchanged.
- **Disassembly** confirms the three selectors (`0x146e61ed`, `0x799320bb`,
  `0xd99a8dc3`) and the `LOG3` topic `0x6747c1…ad39`.
- **Constants recovered** at byte offsets `0x116`, `0x14a`, `0x17e` of the decoded
  runtime bytecode; concatenation yields the flag.

---

## Remediation / Key Takeaways

- **Root cause:** a secret stored as a literal operand inside public bytecode.
  Anyone with the bytecode can read it.
- **Fix:** never embed a secret in deployed code. Compare a *hash* of the input to
  an on-chain digest (`keccak256(input) == storedHash`) or verify a signature —
  the pre-image never needs to appear in the code.
- **Lesson:** for EVM challenges, lift `PUSH*` payloads first; answer constants,
  event topics and storage layouts usually fall straight out. The trailing
  `PUSH2 + SHL` is the standard way short strings are packed into a word, so don't
  ignore sub-`PUSH32` operands.
