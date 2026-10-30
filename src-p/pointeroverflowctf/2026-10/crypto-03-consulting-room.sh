#!/usr/bin/env bash
# POCTF 2026 — The Consulting Room: CBC padding-oracle attack.
#
# For a chosen IV block A and ciphertext block C_i the oracle checks the
# PKCS#7 padding of D(C_i) XOR A in the last block.  Recover D(C_i) byte
# by byte, then P_i = D(C_i) XOR C_{i-1}.
#
# The proxy path silently swallows a request every few tries: connection
# and TLS stay up, the request simply never returns.  HTTP/2 multiplexing
# is what makes this workable — all 256 guesses for a byte go over ONE TLS
# connection as parallel streams, so a swallowed stream does not hold up
# the other 255.  A guess that never answered is the only unknown; it is
# asked again (and only it).  Six streams stay under 1000 requests/minute.
#
# Valid padding answers HTTP 200, invalid answers 400.

URL="https://pointeroverflowctf.com/challenges/consulting-room/oracle"
TOKEN="ak4t2zD6PiHO7CP4prgwl9dr9lCZwTZV"
RECORD="b96f58b4a3be325e9ef5ba2cbbab281bd14dc4310a2cae3ecd4b735b62a155cb8d322da6d36d2d6232be823d88a4bb123147b4f784e9fdd234ea265376de7c6587c26a8d80474173c562daa9a841ca4e"
BLOCK=16
PARALLEL=${PARALLEL:-6}
CHUNK=${CHUNK:-50}
TIMEOUT=${TIMEOUT:-5}
PAUSE=${PAUSE:-1}

# Checkpoint: one line per block, "<target> <first known byte> <D bytes hex>".
# Written after every recovered byte, so a killed run resumes where it stopped.
STATE="${STATE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.consulting-room.state}"
declare -A CACHE

load_state() {
    [[ -s $STATE ]] || return 0
    local t sf sx
    while read -r t sf sx; do
        [[ $t ]] && CACHE[$t]="$sf $sx"
    done < "$STATE"
}

set_state() {
    local t=$1 from=$2 hex=$3 tmp="$STATE.$$"
    if [[ -f $STATE ]]; then
        grep -v "^$t " "$STATE" > "$tmp" 2>/dev/null || true
    else
        : > "$tmp"
    fi
    printf '%s %s %s\n' "$t" "$from" "$hex" >> "$tmp"
    mv "$tmp" "$STATE"
    CACHE[$t]="$from $hex"
}

# One record, with retries only while the answer is missing (000/5xx).
ask() {
    local rec=$1 st try
    for ((try = 0; try < 10; try++)); do
        st=$(curl -sS --http2 -m "$TIMEOUT" -o /dev/null -w '%{http_code}' "$URL" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"record\":\"$rec\"}" 2>/dev/null < /dev/null)
        [[ $st == 200 || $st == 400 ]] && { echo "$st"; return; }
    done
    echo 000
}

# batch OUT; stdin: one "guess record" per line.  Writes "status guess"
# lines to OUT, one per answer that came back.  Each transfer is its own
# --next segment: without it curl applies the last -w/-d to every URL.
# The connection dies after a few dozen requests and everything still
# queued on it comes back empty, so only CHUNK transfers share a
# connection; the next chunk opens a fresh one.
batch() {
    local out=$1 guess rec n=0
    local -a args
    : > "$out"
    while read -r guess rec; do
        if (( n % CHUNK == 0 )); then
            args=(curl -sS --http2 --parallel --parallel-max "$PARALLEL")
        else
            args+=(--next)
        fi
        args+=(-m "$TIMEOUT" -o /dev/null -w "%{http_code} $guess\n" "$URL" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"record\":\"$rec\"}")
        n=$((n + 1))
        if (( n % CHUNK == 0 )); then
            "${args[@]}" >> "$out" 2>/dev/null < /dev/null
            sleep "$PAUSE"
        fi
    done
    (( n % CHUNK )) && "${args[@]}" >> "$out" 2>/dev/null < /dev/null
}

recover_block() {
    local target=$1 p k pad pos hb g c round found head sf sx from hex
    local -a known st todo next
    local out cand start
    out=$(mktemp)
    start=$((BLOCK - 1))
    if [[ -n ${CACHE[$target]:-} ]]; then
        read -r sf sx <<< "${CACHE[$target]}"
        for ((k = sf; k < BLOCK; k++)); do known[k]=$((0x${sx:2*(k-sf):2})); done
        start=$((sf - 1))
        echo "  resume: D bytes $sf..$((BLOCK - 1)) already known" >&2
    fi
    for ((p = start; p >= 0; p--)); do
        pad=$((BLOCK - p))
        head=$(printf '00%.0s' {1..16})
        for ((k = p + 1; k < BLOCK; k++)); do
            printf -v hb '%02x' $(( known[k] ^ pad ))
            pos=$((2 * k))
            head="${head:0:pos}${hb}${head:pos+2}"
        done
        pos=$((2 * p))
        st=()
        todo=()
        for ((g = 0; g < 256; g++)); do todo+=("$g"); done
        for ((round = 1; round <= 10 && ${#todo[@]} > 0; round++)); do
            for g in "${todo[@]}"; do
                printf -v hb '%02x' "$g"
                printf '%s %s\n' "$g" "${head:0:pos}${hb}${head:pos+2}${target}"
            done | batch "$out"
            while read -r c g; do
                [[ $c == 200 || $c == 400 ]] && st[g]=$c
            done < "$out"
            next=()
            for g in "${todo[@]}"; do
                [[ -n ${st[g]:-} ]] || next+=("$g")
            done
            todo=("${next[@]}")
            (( ${#todo[@]} )) && echo "  byte $p: ${#todo[@]} unanswered, re-asking" >&2
        done
        # A handful of guesses can stay unanswered through every batch.  One
        # request at a time through a fresh connection gets an answer where
        # the burst does not, so sweep the leftovers that way.
        if ((${#todo[@]} > 0)); then
            for g in "${todo[@]}"; do
                printf -v hb '%02x' "$g"
                cand="${head:0:pos}${hb}${head:pos+2}${target}"
                [[ $(ask "$cand") == 200 ]] || continue
                if (( p == BLOCK - 1 )); then
                    printf -v hb '%02x' $(( 0x${cand:28:2} ^ 0xff ))
                    [[ $(ask "${cand:0:28}${hb}${cand:30}") == 200 ]] || continue
                fi
                st[g]=200
                break
            done
            echo "  byte $p: ${#todo[@]} swept one by one" >&2
        fi
        found=-1
        for ((g = 0; g < 256; g++)); do
            [[ ${st[g]:-} == 200 ]] || continue
            printf -v hb '%02x' "$g"
            cand="${head:0:pos}${hb}${head:pos+2}${target}"
            if (( p == BLOCK - 1 )); then
                # Last byte: a 0x02 0x02 padding also passes.  Flipping
                # byte 14 keeps a real 0x01 and breaks anything longer.
                printf -v hb '%02x' $(( 0x${cand:28:2} ^ 0xff ))
                [[ $(ask "${cand:0:28}${hb}${cand:30}") == 200 ]] || continue
            fi
            found=$g
            break
        done
        rm -f "$out"
        (( found >= 0 )) || { echo "no valid guess for byte $p" >&2; return 1; }
        known[p]=$(( found ^ pad ))
        printf '  byte %2d  D=%02x\n' "$p" "${known[p]}"
        from=$p
        hex=""
        for ((k = p; k < BLOCK; k++)); do
            printf -v hb '%02x' "${known[k]}"
            hex+=$hb
        done
        set_state "$target" "$from" "$hex"
    done
    KNOWN=("${known[@]}")
}

main() {
    local n i p pos prev target block_hex plain_hex pad len hb
    load_state
    n=$(( ${#RECORD} / (2 * BLOCK) ))
    echo "record: $(( ${#RECORD} / 2 )) bytes, IV + $((n - 1)) blocks"
    plain_hex=""
    for ((i = 1; i < n; i++)); do
        prev=${RECORD:$(( (i - 1) * 2 * BLOCK )):$((2 * BLOCK))}
        target=${RECORD:$(( i * 2 * BLOCK )):$((2 * BLOCK))}
        echo "block $i/$((n - 1))"
        recover_block "$target" || return 1
        block_hex=""
        for ((p = 0; p < BLOCK; p++)); do
            pos=$((2 * p))
            printf -v hb '%02x' $(( KNOWN[p] ^ 0x${prev:pos:2} ))
            block_hex+=$hb
        done
        plain_hex+=$block_hex
        printf '  => %s\n' "$(printf '%s' "$block_hex" | xxd -r -p | cat -v)"
        printf '  .. %s\n' "$(printf '%s' "$plain_hex" | xxd -r -p | cat -v)"
    done
    pad=$(( 0x${plain_hex: -2} ))
    len=$(( ${#plain_hex} - 2 * pad ))
    plain_hex=${plain_hex:0:len}
    printf 'FLAG: %s\n' "$(printf '%s' "$plain_hex" | xxd -r -p)"
}

main

# d14dc4310a2cae3ecd4b735b62a155cb 0 e9201be0e5c5056cb0c48c1d82857b51
# 8d322da6d36d2d6232be823d88a4bb12 0 9c7ff77d3e79e1769c07251050e07bfc
# 3147b4f784e9fdd234ea265376de7c65 0 d9001af2e05b6e3378f5d56dd0eded27
# 87c26a8d80474173c562daa9a841ca4e 12 70d87a63

