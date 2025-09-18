Author: marlithor_cyber (adapted)
Challenge: Hatagawa I (Crypto / PRNG OTP)
Flag: BHFlagY{e73331bbd233950818d09b5f4aa15e80}

Summary (one-line)
Hatagawa I uses a broken one-time pad built from a 64-bit Linear Congruential Generator (LCG). A known 8-byte prefix of the flag lets you recover consecutive internal states; from three consecutive states you solve a linear congruence for A = a^s (mod 2^64), lift A to possible a values (Hensel/2-adic lifting), recover c, regenerate the OTP and decrypt the flag.

Vulnerability / Why this is solvable
The challenge uses an LCG (x ← a*x + c (mod M)) to produce raw 8-byte words which are concatenated to build an OTP. The OTP is XORed with the flag.
The LCG modulus is M = 2^64 (effectively & (2**64 - 1)), and the multiplier a is constrained (a % 8 == 5) which gives a predictable residue mod small powers of two.
You know the first 8 bytes of the plaintext ("BHFlagY{"), so XORing those 8 bytes with the first 8 bytes of ciphertext yields the first PRNG output x1 (as a 64-bit integer).
With at least 3 independent ciphertext captures you can recover three consecutive PRNG outputs x1, x2, x3 (because every Encrypt() consumes s LCG outputs; we extract the first 8 bytes of each ciphertext and invert the known prefix).
From x1, x2, x3 you can form the congruence:
A * (x2 - x1) ≡ (x3 - x2) (mod 2^64)
where A = a^s mod 2^64. Solving this linear congruence gives candidate A values.
Recover a by computing s-th modular roots of A modulo 2^64 using 2-adic (Hensel) lifting (only residues congruent to 5 mod 8 are valid).
Once a is known, compute c from the relation between two consecutive states (taking into account gcd factors from geometric sums), regenerate the OTP and decrypt to get the full flag.
High-level attack steps
Collect captures: Connect to the challenge, choose the Stay a while... option multiple times and save the hex ciphertext outputs (we used CAPTURES = 8).
Detect s: For the first ciphertext, compute s = ceil(len(ct)/8) — the number of LCG outputs consumed per encryption.
Recover first states: For each capture, XOR the first 8 bytes of ciphertext with b'BHFlagY{' to derive the first 64-bit PRNG output for that capture.
Solve linear congruence (for each triple of consecutive states):
Solve A * (x2 - x1) ≡ (x3 - x2) (mod 2^64) for A (there may be multiple solutions due to gcd).
Hensel lift: For each candidate A, compute all a such that a^s ≡ A (mod 2^64) and a % 8 == 5. Lift roots from mod 8 up to mod 2^64.
Solve for c and verify: For each candidate a, compute S = 1 + a + a^2 + ... + a^{s-1} and derive c from the linear relation using modular inverses (handle gcd). Recreate x0, regenerate the OTP, XOR with ciphertext and check for a valid flag format BHFlagY{...}.
Return flag on success.
Important math notes (concise)
Work modulo M = 2^64. When solving A * d2 ≡ d1 (mod M), if g = gcd(d2, M), a solution exists only if d1 % g == 0. The reduced equation is solved modulo M/g.
A = a^s (mod M). Recovering a from A is modular root extraction in modulus 2^k (2-adic). Because a is known to be ≡ 5 (mod 8), that restricts roots and makes Hensel lifting feasible.
S = sum_{i=0}^{s-1} a^i (mod M) appears when relating x states across s steps; use it to compute c with modular inverse of S modulo the reduced modulus M/g.
Script (how to run)
This is the working exploit used during the CTF (offline-ready explanation and online-capable). Save as solvehatagawa1.py and run:

python3 solvehatagawa1.py
It will: connect to HOST:PORT, collect captures, compute s, solve congruences, apply Hensel lifting, reconstruct OTP and print the flag.

Note: In the contest I used CAPTURES = 8. You need at least 3 captures (3 consecutive first-blocks) for the linear congruence step; more captures help reliability.

Key code excerpts (explanatory)
Extract first PRNG output from ciphertext using known prefix:

known_prefix = b'BHFlagY{'
# ct is a ciphertext bytes()
x_first = bytes([ct[i] ^ known_prefix[i] for i in range(8)])
x1 = int.from_bytes(x_first, 'big')
Linear congruence solver for A = a^s (mod 2⁶⁴):

d2 = (x2 - x1) % M
d1 = (x3 - x2) % M
g = gcd(d2, M)
# Check existence: d1 % g == 0
# Solve reduced equation and produce A candidates:
A_candidates = [(A0 + k*(M//g)) % M for k in range(g)]
Hensel lifting (2-adic) to find a with residue 5 mod 8:

Start with residue r = 5 modulo 8, check r^s ≡ A (mod 8).
Iteratively lift from modulus 2^k to 2^{k+1} by testing the two lifts r and r + 2^k.
Continue until k = 63 to reach 64-bit solutions.
Recreate OTP and verify flag:

# compute S = sum_{i=0}^{s-1} a^i mod M
# compute c via modular inversion (account for gcd)
# compute x0 and regenerate s blocks:
x = x0
otp = b''
for _ in range(s):
    x = (a*x + c) % M
    otp += x.to_bytes(8, 'big')
plaintext = bytes([ct[i] ^ otp[i] for i in range(len(ct))])
Final result
Running the exploit recovered the flag:

BHFlagY{e73331bbd233950818d09b5f4aa15e80}
#!/usr/bin/env python3
"""
Exploit for Hatagawa I (updated)

- Automatically detects block count s = ceil(len(ct)/8)
- Solves A = a^s (mod 2^64) via linear congruence and root-lifting
- Solves for c and verifies by regenerating OTP and decrypting
"""

import socket, re
from math import ceil, gcd
from typing import List

HOST = "34.252.33.37"    
PORT = 31183   
CAPTURES = 8  # collect a few; we need at least 3
M = 1 << 64

def recv_until(sock: socket.socket, stop: bytes = b'>') -> bytes:
    data = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if stop in data:
            break
    return data

def parse_ciphertext_chunk(payload: bytes) -> bytes:
    """
    Extract the hex ciphertext embedded in the ASCII river art.
    We look for a pattern like:
      |   ~~~ <hex> ~
    and return bytes() of that hex.
    """
    lines = payload.splitlines()
    for line in lines:
        if b'|   ~~~ ' in line and b' ~' in line:
            try:
                part = line.split(b'|   ~~~ ', 1)[1]
                hexpart = part.split(b' ~', 1)[0].strip()
                if re.fullmatch(b'[0-9a-fA-F]+', hexpart):
                    return bytes.fromhex(hexpart.decode())
            except Exception:
                continue
    return b''

def collect_ciphertexts(n: int) -> List[bytes]:
    cts = []
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        recv_until(s, stop=b'>')
        for i in range(n):
            s.sendall(b's\n')
            data = recv_until(s, stop=b'>')
            ct = parse_ciphertext_chunk(data)
            if not ct:
                raise RuntimeError(f"Failed parsing ciphertext #{i+1}")
            cts.append(ct)
    return cts

def solve_linear_for_A(x1: int, x2: int, x3: int) -> List[int]:
    """
    Solve A * (x2 - x1) ≡ (x3 - x2) (mod 2^64).
    Return all solutions A (usually few).
    """
    d2 = (x2 - x1) % M
    d1 = (x3 - x2) % M
    g = gcd(d2, M)
    if d1 % g != 0:
        return []
    d2r = d2 // g
    d1r = d1 // g
    Mr = M // g
    inv = pow(d2r, -1, Mr)
    A0 = (d1r * inv) % Mr
    # full solutions are A0 + k * Mr for k in 0..g-1
    return [(A0 + k * Mr) % M for k in range(g)]

def hensel_lift_root_general(A: int, e: int, residue_mod8: int = 5) -> List[int]:
    """
    Find roots 'a' modulo 2^64 such that a^e ≡ A (mod 2^64) and a % 8 == residue_mod8.
    Uses a simple 2-adic lifting: start with residues mod 8 that fit constraint,
    then iteratively lift to next bit by checking both choices r and r+2^k.
    This is correct for lifting in power-of-two modulus.
    """
    # quick necessary condition: A % 2 == (residue_mod8**e) % 2
    # But we'll run full lifting starting from modulus 8.
    if residue_mod8 % 2 == 0:
        return []
    # Start with the single residue residue_mod8 (e.g. 5)
    # Validate it matches mod 8:
    if pow(residue_mod8, e, 8) != (A % 8):
        return []
    candidates = [residue_mod8]
    # lift from modulus 8 up to 2^64
    for k in range(3, 64):
        mod_next = 1 << (k + 1)
        targ = A % mod_next
        add = 1 << k
        new_cands = []
        for r in candidates:
            # two lifts r or r + 2^k
            for inc in (0, add):
                cand = r + inc
                if pow(cand, e, mod_next) == targ:
                    new_cands.append(cand)
        if not new_cands:
            return []
        # deduplicate
        candidates = sorted(set(new_cands))
    return candidates

def geometric_sum_mod(a: int, s: int) -> int:
    """Compute S = 1 + a + a^2 + ... + a^{s-1} mod M."""
    total = 0
    cur = 1
    for _ in range(s):
        total = (total + cur) % M
        cur = (cur * a) % M
    return total

def solve_for_c_and_verify(a: int, A: int, B: int, x1: int, s: int, ciphertexts: List[bytes]) -> bytes:
    """
    Given a candidate 'a', attempt to solve for c and verify by regenerating OTP and decrypting.
    """
    S = geometric_sum_mod(a, s)  # S = sum_{i=0}^{s-1} a^i
    g = gcd(S, M)
    if B % g != 0:
        return b''
    Sr = S // g
    Br = B // g
    Mr = M // g
    try:
        inv_Sr = pow(Sr, -1, Mr)
    except ValueError:
        return b''
    c0 = (Br * inv_Sr) % Mr
    # full solutions c = c0 + t*Mr for t in range(g)
    for t in range(g):
        c = (c0 + t * Mr) % M
        if c % 2 == 0:
            continue  # c must be odd
        # compute x0 from x1 = a*x0 + c mod M
        try:
            inv_a = pow(a, -1, M)
        except ValueError:
            continue
        x0 = ((x1 - c) * inv_a) % M
        # regen OTP: s calls per encryption produce s*8 bytes
        x = x0
        otp = b''
        for _ in range(s):
            x = (a * x + c) % M
            otp += x.to_bytes(8, 'big')
        # decrypt first ciphertext
        pt = bytes([c1 ^ o for c1, o in zip(ciphertexts[0], otp)])
        if pt.startswith(b'BHFlagY{') and pt.endswith(b'}'):
            return pt
    return b''

def main():
    print("[*] Collecting ciphertexts from remote...")
    cts = collect_ciphertexts(CAPTURES)
    print(f"[*] Collected {len(cts)} ciphertexts (each {len(cts[0])} bytes)")

    # determine s (how many Get() calls per Encrypt)
    ctlen = len(cts[0])
    s = ceil(ctlen / 8)
    print(f"[*] Detected ciphertext length {ctlen} bytes -> s = {s} Get() calls per Encrypt")

    known_prefix = b'BHFlagY{'  # 8 bytes known
    # Derive first-state integers from first 8 bytes of each ciphertext
    x_first_states = []
    for ct in cts:
        if len(ct) < 8:
            raise RuntimeError("ciphertext too short")
        xb = bytes([ct[i] ^ known_prefix[i] for i in range(8)])
        x_first_states.append(int.from_bytes(xb, 'big'))

    n = len(x_first_states)
    for i in range(n - 2):
        x1 = x_first_states[i]
        x2 = x_first_states[i + 1]
        x3 = x_first_states[i + 2]
        print(f"[*] Trying triple indices {i},{i+1},{i+2}")
        A_cands = solve_linear_for_A(x1, x2, x3)
        if not A_cands:
            print("[!] linear congruence gave no A candidates; next triple")
            continue
        print(f"[*] {len(A_cands)} A candidate(s) from linear solve")
        for A in A_cands:
            B = (x2 - (A * x1)) % M
            # find s-th roots a of A with residue 5 mod 8
            a_cands = hensel_lift_root_general(A, s, residue_mod8=5)
            if not a_cands:
                print("[!] no 'a' candidates for this A (root-lift failed)")
                continue
            print(f"[*] {len(a_cands)} a-candidate(s) for this A")
            for a in a_cands:
                pt = solve_for_c_and_verify(a, A, B, x1, s, cts)
                if pt:
                    print("[+] Success! Flag recovered:")
                    print(pt.decode(errors='replace'))
                    return
    print("[-] Failed to recover flag. Try increasing CAPTURES and re-running.")

if __name__ == "__main__":
    main()
Mitigations / Lessons learned
Never use a deterministic PRNG (LCG) to generate a one-time pad. OTP requires a truly random, non-reproducible key of the same length as the message.
If a PRNG must be used, ensure state or outputs are not reused across messages and that outputs are cryptographically secure (e.g., use a CSPRNG such as /dev/urandom, libsodium, or an HMAC-DRBG).
Avoid exposing any known plaintext at predictable positions — even leaking a short prefix can let an attacker recover internal PRNG state.
Use authenticated encryption (AEAD) instead of raw XOR with an OTP to protect integrity and limit information leaks.
Repro / Attachments
solvehatagawa1.py — full exploit (connects to remote, collects captures, recovers parameters, prints flag).
