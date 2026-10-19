# Matryoshka

- **CTF:** NexSec CTF
- **Category:** Reverse Engineering (.NET / crypto)
- **Artifacts:** `matryoshka.exe`, `doll-*.dll` (32 nested assemblies), `solve.py`, `flag.py`
- **Flag:** `nexsec26{nexsec26{nexsec26{🚩}}}`

---

## Overview

The handout is a literal **matryoshka doll** of .NET assemblies. `matryoshka.exe`
carries a binary tree of encrypted `doll-*.dll` resources named with binary paths
(`doll-0`, `doll-1`, `doll-00`, … `doll-1111`). Each doll:

1. is an AES-CBC blob whose key is derived from its parent,
2. constrains a short password with HMACs, and
3. invokes its two children.

The innermost doll (path `1111`) carries the flag, encrypted with
`SHA-256(password)`. The solve is a chain: recover the root key → derive every
child key → read the per-doll HMAC constraints → brute the password → decrypt the
flag.

---

## Step 1 — Handouts

```
$ sha256sum matryoshka.exe doll-1111.dll flag.py solve.py
ee46a9d2418b21358ebc827c8d2bc0256315dfa4f78728e0078bc6bc191edafd  matryoshka.exe
c52a74c9251fab0aceca24a87d92d68a7903a9ec55fe707d4f679dbe3f60e428  doll-1111.dll
816a57b6cc5b1e811a1176480a2461eb9f516653b9e872f96f3aab2199ae4e71  flag.py
9f2cc9aa9661d06c94c06afef6bcdd495324032e480cfd830eddb903b85f3195  solve.py
```

Both `.exe` and `.dll` are **managed .NET assemblies**. Inside `matryoshka.exe`,
the `doll-*` resources are *not* PE files — they are AES blobs.

---

## Step 2 — Decompile the dolls

Opened `matryoshka.exe` in **Dogbolt (dogbolt.org)** for a first look at the
managed metadata, then decompiled the assemblies with **`ilspycmd`** (the tool
`solve.py` drives). Every doll exposes the same `Doll` class shape:

```csharp
public static readonly string   ASM_NAME  = "doll-1111";
public static readonly string   PATH      = "1111";
public static readonly int[]    INDICES   = new int[...];
public static readonly string[] HMACS     = new string[...] { "<64 hex chars>", ... };
public static readonly string   OPEN_LINE = "Doll 0xF, the innermost, ...";
public static readonly bool     CARRIES_FLAG = true;
public static readonly string   FLAG_ENC  = "<128 hex chars>";
public static readonly string   CHILD0_RES, CHILD1_RES;
```

And two crypto helpers worth memorising:

```csharp
public static byte[] DeriveChildKey(byte[] parentKey, string childPath)
    => Sha256(parentKey || ASCII(childPath));

public static byte[] DecryptBlob(byte[] blob, byte[] key) {
    IV = blob[0..16]; aes.Key = key; aes.IV = IV; aes.Mode = CBC; aes.Padding = PKCS7;
    return aes.Decrypt(blob[16..]);
}
```

So every child key is `SHA-256(parentKey ‖ fullChildPath)`, and every resource is
`16-byte IV ‖ AES-CBC ciphertext`.

---

## Step 3 — Recover the root key

The root key is not stored — `matryoshka.exe` XORs three embedded 32-byte
constants to build it:

```
k1 = 328c8951475e0d2c71a84c2f619af94727bef60eaadbe557cf5f82afd98d531b
k2 = 1a685de80dadec0efc1a32e0d07fc450e68f1c348c9c00ad8a39395b380911ba
k3 = 0641f85debb485f588745a946b1cbfd76257b2b18504b40ff60f304bbded9bc1

base = k1 ^ k2 ^ k3
     = 2ea52ce4a14764d705c6245bdaf982c0a366588ba34351f5b3698bbf5c69d960
```

Verified independently:

```
$ python3 -c "k=['328c...531b','1a68...11ba','0641...9bc1']; x=bytes(a^b^c for a,b,c in zip(*[bytes.fromhex(h) for h in k])); print(x.hex())"
2ea52ce4a14764d705c6245bdaf982c0a366588ba34351f5b3698bbf5c69d960
```

---

## Step 4 — Walk the tree (`solve.py`)

`solve.py` does the whole descent automatically: BFS over the path set, derive the
key, **decrypt the child blob, dump it as `doll-<path>.dll`, decompile with
`ilspycmd`, and recurse** until it finds the doll whose `CARRIES_FLAG = true`:

```python
queue = []
for suf in ["0", "1"]:
    queue.append((suf, derive(base, suf), root/"decompiled"/f"doll-{suf}"))

while queue:
    path, key, resfile = queue.pop(0)
    if not resfile.exists(): continue
    pt = decrypt(resfile.read_bytes(), key)
    (root/f"doll-{path}.dll").write_bytes(pt)
    subprocess.run([ilspy, "-p", "-o", str(decdir), str(dll)], check=True)
    txt = (decdir/"Doll.cs").read_text()
    print("=== path", path, "CARRIES_FLAG true?", "true" in txt.split("CARRIES_FLAG")[1][:20])
    if "CARRIES_FLAG = true" in txt:
        print(">>> FLAG DOLL at", path); print(txt); break
    for suf in ["0", "1"]:
        cand = decdir/f"doll-{path+suf}"
        if cand.exists():
            queue.append((path+suf, derive(key, path+suf), cand))
```

This lands on `doll-1111` (and, along the way, 16 sibling dolls whose `Doll.cs`
files supply the password constraints).

---

## Step 5 — Read the password constraint

Each `Doll.cs` carries `INDICES` and a matching `HMACS` list. The check is one
HMAC per index:

```
HMAC-SHA256(key, [idx, pw[idx]])                       # normal doll
HMAC-SHA256(key, [idx, pw[idx]>>4, ((pw[idx]&0xF)>>level) & 1])   # level-3 doll
```

`idx` and the trailing bits are *public*; only `pw[idx]` is unknown. So each
constraint is a **256-way** search, and the intersection across all dolls pins
each of the 16 password bytes.

---

## Step 6 — First crack attempts (and what broke)

`flag.py` was built up in stages, and the terminal transcript captures every dead
end:

**6a. A parse crash.** The regex assumed the `INDICES` array was always
initialised:

```
$ python3 flag.py
  File ".../flag.py", line 30, in parse_doll
    inds = [int(x) for x in re.search(r"INDICES = new int\[\d+\] \{([^}]*)\}", t).group(1).split(",")]
AttributeError: 'NoneType' object has no attribute 'group'
```

Some dolls declare the array size but leave the braces empty, so the optional
group must be tolerated.

**6b. A missing doll.**

```
skip (no Doll.cs): 0100
total constraints: 63
```

One doll's decompile output didn't have a `Doll.cs` at the expected path yet (63
constraints instead of 64).

**6c. The 14^16 blow-up.** With a naive single-field HMAC model, every index came
back with 14 candidates:

```
idx 0 cands [112, 113, 114, ... 126, 127]
...
cand counts: [14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14]
^CTraceback (most recent call last):
  File ".../flag.py", line 67, in <module>
    pw = bytes(combo)
KeyboardInterrupt
```

`14^16 ≈ 2.2·10^18` combinations — the product search never finished. The fix was
to model the **level-3 dolls** correctly (`bytes([idx, v>>4, ((v&0xF)>>lvl)&1])`),
which collapses those candidates.

**6d. A probe, and its own typo.**

```
$ python3 test.py
python3: can't open file '.../Matryoshka/test.py': [Errno 2] No such file or directory
$ /usr/bin/python ".../doll001_dec/test.py"
1111 idx13 hits: [111]
Traceback (most recent call last):
  File ".../doll001_dec/test.py", line 6, in <module>
    print("k1111:", keys["1111"].hex())
NameError: name 'keys' is not defined
```

---

## Step 7 — Pin the password

After the level-3 fix, every index collapses to a single candidate:

```
$ python3 flag.py
total constraints: 64
idx 0 cands [114]
idx 1 cands [104]
idx 2 cands [107]
idx 3 cands [97]
idx 4 cands [68]
idx 5 cands [119]
idx 6 cands [102]
idx 7 cands [105]
idx 8 cands [110]
idx 9 cands [77]
idx 10 cands [101]
idx 11 cands [80]
idx 12 cands [99]
idx 13 cands [111]
idx 14 cands [108]
idx 15 cands [122]
cand counts: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
pw: b'rhkaDwfinMePcolz'
FLAG: nexsec26{nexsec26{nexsec26{🚩}}}
```

`flag.py` also confirms the password against the stored digest before decrypting:
`SHA-256(pw) == 77aa4d230ca164172ea2c972e207cb93dae2d0bd5e5fd3234ff4b5ea8874e345`.

---

## Step 8 — Decrypt the flag

`key = SHA-256("rhkaDwfinMePcolz")`, then AES-CBC decrypt `FLAG_ENC` from
`doll-1111`:

```
FLAG_ENC = 5311cf63109a5a9082d797f0e917433f58f6c3b79bb1dd8925a4d82d95754aef
           3865420feea10448db156277d2ea54f89ea4fee7b65f87cdf10dc9863329da93

plaintext hex = 6e657873656332367b 6e657873656332367b 6e657873656332367b f09f9aa9 7d7d7d
              = "nexsec26{"        "nexsec26{"        "nexsec26{"        🚩        "}}}"
```

---

## Flag & Proof of Concept

```
nexsec26{nexsec26{nexsec26{🚩}}}
```

Recovered values:

| Item | Value |
|---|---|
| Root key | `2ea52ce4a14764d705c6245bdaf982c0a366588ba34351f5b3698bbf5c69d960` |
| Password | `rhkaDwfinMePcolz` |
| `SHA-256(pw)` | `77aa4d230ca164172ea2c972e207cb93dae2d0bd5e5fd3234ff4b5ea8874e345` |
| Flag doll | `doll-1111` (`PATH = "1111"`, `CARRIES_FLAG = true`) |

Reproduction:

```bash
cd "Reverse Engineering/Matryoshka"
sha256sum matryoshka.exe doll-1111.dll flag.py
python3 flag.py     # -> pw: b'rhkaDwfinMePcolz'  /  FLAG: nexsec26{nexsec26{nexsec26{🚩}}}
```

---

## Evidence

- **Artifacts hashed** (Step 1); originals unchanged.
- **Dogbolt used** for the managed-binary pass; **`ilspycmd`** decompiles each
  decrypted doll inside `solve.py`.
- **Key chain verified** independently: `XOR(k1,k2,k3)` equals the `base`
  constant consumed by `flag.py`.
- **Recorded terminal transcript**
  (`~/.config/Code/User/workspaceStorage/5054bb98eceb64e66c772c9bbbb23c0d/state.vscdb`):
  the `parse_doll` `AttributeError`, the `14^16` `KeyboardInterrupt`, the
  `test.py` `NameError`, and the final `pw:` / `FLAG:` lines above.
- **Unique password:** all 16 indices report `cand counts: [1, 1, …]`.

---

## Remediation / Key Takeaways

- **Root cause:** a public, deterministic key-derivation chain plus a *byte-at-a-time*
  keyed check. Everything needed to recover the secret is derivable from the
  shipped artifacts, so the whole scheme reduces to a handful of 256-way searches.
- **Fix:** derive keys from a real KDF with a per-install secret
  (`HKDF`/`PBKDF2` with a server-side salt), never encrypt the protected value
  with a key derivable from public data, and validate the password against a
  single slow salted hash instead of per-byte HMACs (which leak one index at a
  time).
- **Lesson:** "nested" does not mean "hard". When each link is deterministic and
  invertible, recovering the root recovers everything. The `HMAC(per-index byte)`
  construction is especially weak — it turns one global password check into 16
  independent 256-entry searches.
