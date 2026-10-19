# NexSec CTF — Writeup Index

Reproducible writeups for the challenges solved, one file per challenge. Each is
written as a **step-by-step walkthrough** in the order it was actually solved:
handout → decompile → spot the bug → iterate → flag.

> **Disclosure**
>
> - Other AI tools were used to produce these writeups (my DeepSeek account was suspended).
> - All code and terminal histories are stored locally and were used here instead of re-running the challenges.

## Tooling

- Reverse-engineering targets were decompiled with **Dogbolt (dogbolt.org)** —
  Binary Ninja / Hex-Rays / Ghidra views. Brave history records the Decompiler
  Explorer sessions during the CTF window (e.g. `dogbolt.org/?id=6eb64041-…` and
  `…=1b74f315-…` on **2026-10-17 11:22**).
- `.NET` dolls (Matryoshka) were additionally decompiled with **`ilspycmd`**;
  EVM bytecode (Very Fest) with **`re.hanz.dev`**; the custom VM (Bytecode Bakery)
  with the supplied **`disasm.py`**.

| # | Challenge | Category | Flag | Writeup |
|---|---|---|---|---|
| 1 | Bytecode Bakery | Reverse Engineering | `nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}` | [Bytecode Bakery.md](./Bytecode%20Bakery.md) |
| 2 | Very Fest | Misc (EVM) | `nexsec26{decentralization_means_giving_up_dominance_over_security}` | [Very Fest.md](./Very%20Fest.md) |
| 3 | Matryoshka | Reverse Engineering | `nexsec26{nexsec26{nexsec26{🚩}}}` | [Matryoshka.md](./Matryoshka.md) |
| 4 | Flagchecker | Reverse Engineering | `nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}` | [Flagchecker.md](./Flagchecker.md) |
| 5 | Gossip | Pwn | `nexsec26{6e75740b9b2285abb6ad864c1445c3f398356116ac7a07fa9c51f2abfbb12c3a}` | [Gossip.md](./Gossip.md) |

## Evidence sources

- **Bytecode Bakery / Very Fest / Matryoshka** — reproduced directly from the
  handout files (solver output + decoded constants); Matryoshka also has the
  archived terminal transcript under
  `~/.config/Code/User/workspaceStorage/5054bb98eceb64e66c772c9bbbb23c0d/`.
- **Flagchecker** — reproducible locally (`angr`); the archived VSCode
  integrated-terminal scrollback records `python solve.py` ending in
  `FOUND FLAG: nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}`.
- **Gossip** — remote instance (`koala.nexsec.my`) is no longer reachable; the
  archived terminal scrollback records the exploit run printing
  `FLAG: nexsec26{6e75740b…12c3a}`. Offsets and script are preserved unchanged.
  50 intermediate `exploit.py` revisions survive in VSCode local history
  (`~/.config/Code/User/History/-6ff3f023/`).

## Evidence standard

Each writeup contains: challenge overview, hashed artifacts (`sha256sum`), the
exact solve/exploit code, a recorded command transcript, the recovered flag, and
takeaways.
