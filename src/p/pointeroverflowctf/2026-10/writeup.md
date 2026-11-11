# Pointer Overflow CTF 2026

Writeups for the three crypto challenges released in the October wave. The
solver for each challenge lives in the same directory as this file.

## 1. Letters Never Sent

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

## 2. Apparatus

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

## 3. The Consulting Room

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

## Summary

| # | Challenge | Technique | Flag |
|---|-----------|-----------|------|
| 1 | Letters Never Sent | Beaufort cipher, compass-rose key | `POCTF{2.1619.DDSVGT4WDHZ47VOL.KUJZW6I6WLD4AARQIBLXTGJ7HZ}` |
| 2 | Apparatus | Game-tree key recovery, printable-ASCII Vigenère | `POCTF{5.1619.BFNVVDUWGGVY4XRL.GBCZ7XM63RBP6YCC52GYYRHEXZ}` |
| 3 | The Consulting Room | CBC padding oracle over multiplexed HTTP/2 | `POCTF{72.1619.SJM23L4UOHQLVK2A.7T27T36CQJKWPXIV5KB5W5MTPF}` |
