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
