#!/usr/bin/env python3
"""
VGX — educational 64-bit Feistel cipher with weak/legacy/strong modes
and ECB / OFB / CTR ciphermodes.

DISCLAIMER: This is NOT GE/ERICSSON/M/A-COM/TYCO/HARRIS/L3/Acme/Wayne Industries,etc VGE and is NOT compatible with any of their encryption products.

Block size: 64 bits (8 bytes)
Key size  : 64 bits (8 bytes)
"""

import argparse
import sys
from dataclasses import dataclass
from typing import List, Tuple, Optional


# -----------------------------
# Helpers: parsing / formatting
# -----------------------------

def hex_to_bytes(s: str, expected_len: Optional[int] = None) -> bytes:
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 != 0:
        raise ValueError("Hex string must have an even number of characters.")
    b = bytes.fromhex(s)
    if expected_len is not None and len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)} bytes.")
    return b

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def parse_cue(cue_str: str) -> bytes:
    raw = cue_str.replace(",", " ").split()
    if len(raw) != 8:
        raise ValueError("CUE must have exactly 8 decimal byte values (0–255).")
    vals = []
    for x in raw:
        v = int(x, 10)
        if not (0 <= v <= 255):
            raise ValueError("Each CUE byte must be in 0..255.")
        vals.append(v)
    return bytes(vals)

def u32(x: int) -> int:
    return x & 0xFFFFFFFF

def rol32(x: int, r: int) -> int:
    r &= 31
    return u32((x << r) | (x >> (32 - r)))

def ror32(x: int, r: int) -> int:
    r &= 31
    return u32((x >> r) | (x << (32 - r)))

def bytes_to_u64_be(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)

def u64_to_bytes_be(x: int) -> bytes:
    return int(x & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big", signed=False)

def split_u64(x: int) -> Tuple[int, int]:
    return (u32(x >> 32), u32(x))

def join_u64(L: int, R: int) -> int:
    return ((L & 0xFFFFFFFF) << 32) | (R & 0xFFFFFFFF)


# -----------------------------
# Nonlinear components
# -----------------------------

SBOX8 = bytes([
    0x63,0x7C,0x5A,0xB1,0x2F,0x9D,0xE3,0x08,0xD6,0x4B,0xA9,0x1C,0xF2,0x77,0x0E,0x85,
    0x91,0x3D,0xC8,0x24,0x6E,0x10,0xAF,0x59,0xE8,0x02,0xB7,0x46,0x7F,0xCC,0x13,0x9A,
    0x2A,0xF0,0x55,0x18,0x6B,0xDE,0x04,0xA1,0x87,0x39,0xC1,0x73,0x0B,0xED,0x96,0x2D,
    0xB5,0x48,0x9F,0x07,0xE1,0x62,0x14,0xAD,0x3A,0xC6,0x70,0x1F,0x88,0xF9,0x25,0xD0,
    0x4E,0xA6,0x0D,0x97,0x21,0x6C,0xDB,0x58,0xF3,0x36,0x82,0x1A,0xBF,0x05,0x9C,0xE7,
    0x11,0xAE,0x67,0xC9,0x2C,0xF6,0x43,0x8E,0xD4,0x19,0x7A,0xB8,0x00,0xEC,0x95,0x3F,
    0xCA,0x2E,0x74,0x0A,0x9B,0xE0,0x17,0xB2,0x4C,0x8B,0xF5,0x60,0x26,0xD1,0x3C,0xA8,
    0xF8,0x41,0x9E,0x0F,0x6A,0xD8,0x30,0xC5,0x57,0x12,0xAB,0xE9,0x03,0xB9,0x7E,0x24,
    0x90,0x1D,0xC7,0x69,0x2B,0xF1,0x56,0x8D,0xD7,0x4A,0xA0,0x1B,0xF7,0x76,0x0C,0x86,
    0x92,0x3E,0xC0,0x27,0x6F,0x15,0xAC,0x5B,0xE2,0x09,0xB6,0x47,0x7D,0xCD,0x16,0x98,
    0x29,0xF4,0x54,0x1E,0x68,0xDF,0x06,0xA2,0x84,0x38,0xC2,0x72,0x0F,0xEA,0x94,0x2F,
    0xB4,0x4D,0x9A,0x01,0xE6,0x61,0x13,0xAA,0x3B,0xC4,0x71,0x1C,0x89,0xF2,0x23,0xD2,
    0x4F,0xA7,0x0E,0x93,0x20,0x6D,0xDA,0x5C,0xF0,0x37,0x83,0x1F,0xBE,0x04,0x9D,0xE5,
    0x10,0xAF,0x66,0xCB,0x2D,0xF3,0x42,0x8F,0xD5,0x18,0x79,0xBA,0x01,0xEB,0x97,0x3E,
    0xC8,0x2F,0x75,0x0B,0x99,0xE1,0x16,0xB3,0x4B,0x8A,0xF4,0x65,0x27,0xD3,0x3D,0xA9,
    0xF9,0x40,0x9F,0x0D,0x6C,0xD9,0x31,0xC3,0x55,0x13,0xA8,0xE8,0x02,0xBB,0x7F,0x22,
])

def sbox_layer_u32(x: int, weak: bool) -> int:
    b = [(x >> shift) & 0xFF for shift in (24, 16, 8, 0)]
    if weak:
        def w(bi: int) -> int:
            return (bi ^ 0xAA) & 0xFF
        y = [w(bi) for bi in b]
    else:
        y = [SBOX8[bi] for bi in b]
    return u32((y[0] << 24) | (y[1] << 16) | (y[2] << 8) | y[3])

def permute_u32(x: int, weak: bool) -> int:
    if weak:
        return rol32(x, 3) ^ ror32(x, 5)
    x ^= rol32(x, 7)
    x ^= ror32(x, 11)
    x = u32(((x & 0x0F0F0F0F) << 4) | ((x & 0xF0F0F0F0) >> 4))
    x ^= rol32(x, 13)
    return x

def F(right: int, subkey: int, weak_sbox: bool, weak_perm: bool) -> int:
    x = u32(right ^ subkey)
    if not weak_sbox and "SBOX8_STRONG" in globals():
        b = [(x >> shift) & 0xFF for shift in (24, 16, 8, 0)]
        b = [SBOX8_STRONG[v] for v in b]
        x = u32((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3])
    else:
        x = sbox_layer_u32(x, weak=weak_sbox)
    x = permute_u32(x, weak=weak_perm)
    x ^= rol32(x, 9)
    x ^= (x * 0x7F4A7C15) & 0xFFFFFFFF
    return u32(x)


# -----------------------------
# Key schedule
# -----------------------------

@dataclass
class Params:
    rounds: int
    weakness: str
    verbose: bool
    ciphermode: str

def derive_subkeys(key8: bytes, cue8: bytes, params: Params) -> List[int]:
    k = bytes_to_u64_be(key8)
    c = bytes_to_u64_be(cue8)
    weak = params.weakness
    seed = k ^ (rol32(u32(c >> 32), 9) << 32) ^ u32(c)
    Ls, Rs = split_u64(seed)
    subkeys: List[int] = []

    if weak == "none":
        # Build a keyed variant S-box
        global SBOX8_STRONG
        rot = (sum(key8) + sum(cue8)) % 256
        SBOX8_STRONG = bytes(SBOX8[(i + rot) % 256] ^ key8[i % 8] for i in range(256))

    for r in range(params.rounds):
        if weak == "very_weak":
            t = (k ^ c) & 0x000000FFFFFFFFFF
            base = u32((t ^ (t >> 8) ^ (t >> 16)) & 0xFFFFFFFF)
            sk = rol32(base, (r * 3) & 31)
            if r >= 4:
                sk = subkeys[r % 4]
        elif weak == "legacy_weak":
            if r == 0:
                Ls ^= u32(c >> 32)
                Rs ^= u32(c)
            sk = u32(rol32(Ls, (r + 1)) ^ ror32(Rs, (r + 5)) ^ (0xA5A5A5A5 ^ r))
            if r >= 2:
                sk = subkeys[r % 2]
        else:  # strong "none" mode
            cue_mix = u32(((c >> ((r % 8) * 8)) & 0xFF) * 0x01010101)
            Ls = u32((Ls + rol32(Rs, (r * 3 + 5) & 31) + 0x9E3779B9 + cue_mix) ^ r)
            Rs = u32((Rs ^ rol32(Ls, (r * 7 + 11) & 31)) + (cue_mix ^ (k & 0xFFFFFFFF)))
            sk = u32(rol32(Ls ^ Rs, (r * 5 + 9) & 31) + 0xA5A5A5A5)
        subkeys.append(sk)
    return subkeys


# -----------------------------
# Feistel core
# -----------------------------

def encrypt_block(block8: bytes, subkeys: List[int], params: Params) -> bytes:
    x = bytes_to_u64_be(block8)
    L, R = split_u64(x)
    weak_sbox = params.weakness in ("legacy_weak", "very_weak")
    weak_perm = params.weakness == "very_weak"
    if params.verbose:
        print(f"  [*] Encrypt block")
        print(f"      L0={L:08X} R0={R:08X}")
    for r, sk in enumerate(subkeys, start=1):
        f = F(R, sk, weak_sbox, weak_perm)
        L, R = R, u32(L ^ f)
        if params.verbose:
            print(f"      r{r:02d} sk={sk:08X} f={f:08X} L={L:08X} R={R:08X}")
    out = join_u64(R, L)
    return u64_to_bytes_be(out)

def decrypt_block(block8: bytes, subkeys: List[int], params: Params) -> bytes:
    x = bytes_to_u64_be(block8)
    R, L = split_u64(x)
    weak_sbox = params.weakness in ("legacy_weak", "very_weak")
    weak_perm = params.weakness == "very_weak"
    if params.verbose:
        print(f"  [*] Decrypt block")
        print(f"      L0={L:08X} R0={R:08X}")
    for r, sk in enumerate(reversed(subkeys), start=1):
        f = F(L, sk, weak_sbox, weak_perm)
        R, L = L, u32(R ^ f)
        if params.verbose:
            print(f"      r{r:02d} sk={sk:08X} f={f:08X} L={L:08X} R={R:08X}")
    out = join_u64(L, R)
    return u64_to_bytes_be(out)


# -----------------------------
# Modes of operation
# -----------------------------

def pad_pkcs7(data: bytes, block_size: int = 8) -> bytes:
    pad = block_size - (len(data) % block_size)
    if pad == 0:
        pad = block_size
    return data + bytes([pad]) * pad

def unpad_pkcs7(data: bytes, block_size: int = 8) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty data.")
    pad = data[-1]
    if pad < 1 or pad > block_size:
        raise ValueError("Invalid PKCS#7 padding.")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid PKCS#7 padding bytes.")
    return data[:-pad]

def ecb_encrypt(plain: bytes, subkeys: List[int], params: Params) -> bytes:
    pt = pad_pkcs7(plain)
    out = bytearray()
    for i in range(0, len(pt), 8):
        out += encrypt_block(pt[i:i+8], subkeys, params)
    return bytes(out)

def ecb_decrypt(cipher: bytes, subkeys: List[int], params: Params) -> bytes:
    if len(cipher) % 8 != 0:
        raise ValueError("ECB ciphertext length must be a multiple of 8 bytes.")
    out = bytearray()
    for i in range(0, len(cipher), 8):
        out += decrypt_block(cipher[i:i+8], subkeys, params)
    return unpad_pkcs7(bytes(out))

def ofb_crypt(data: bytes, subkeys: List[int], params: Params, iv: bytes) -> bytes:
    """OFB: keystream = E_K(prev), XOR with data. Encrypt/decrypt are identical."""
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes for OFB.")
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 8):
        ks = encrypt_block(prev, subkeys, params)
        block = data[i:i+8]
        out += bytes(b ^ ks[j] for j, b in enumerate(block))
        prev = ks
    return bytes(out)

def ctr_crypt(data: bytes, subkeys: List[int], params: Params, iv: bytes) -> bytes:
    """CTR: keystream = E_K(counter), XOR with data. Encrypt/decrypt are identical."""
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes for CTR.")
    counter = int.from_bytes(iv, "big")
    out = bytearray()
    for i in range(0, len(data), 8):
        ks = encrypt_block(counter.to_bytes(8, "big"), subkeys, params)
        block = data[i:i+8]
        out += bytes(b ^ ks[j] for j, b in enumerate(block))
        counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF
    return bytes(out)


# -----------------------------
# CLI
# -----------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="VGX — educational 64-bit Feistel cipher.")
    ap.add_argument("--mode", choices=["encrypt", "decrypt"], required=True)
    ap.add_argument("--ciphermode", choices=["ecb", "ofb", "ctr"], default="ecb")
    ap.add_argument("--key", required=True)
    ap.add_argument("--cue", required=True)
    ap.add_argument("--plain", help="Plaintext as hex for encryption")
    ap.add_argument("--cipher", help="Ciphertext as hex for decryption")
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--weakness", choices=["none", "legacy_weak", "very_weak"], default="legacy_weak")
    ap.add_argument("--iv", help="IV as 8-byte hex for OFB/CTR")
    ap.add_argument("--verbose", action="store_true")

    args = ap.parse_args()

    # Strong mode defaults to 16 rounds if user left default at 8
    if args.weakness == "none" and args.rounds == 8:
        args.rounds = 16

    key8 = hex_to_bytes(args.key, expected_len=8)
    cue8 = parse_cue(args.cue)
    params = Params(
        rounds=args.rounds,
        weakness=args.weakness,
        verbose=args.verbose,
        ciphermode=args.ciphermode,
    )
    subkeys = derive_subkeys(key8, cue8, params)

    # Optional IV (required for OFB/CTR)
    iv = None
    if args.ciphermode in ("ofb", "ctr"):
        if not args.iv:
            sys.exit(f"{args.ciphermode.upper()} mode requires --iv (8-byte hex).")
        iv = hex_to_bytes(args.iv, expected_len=8)

    # Verbose parameter dump
    if args.verbose:
        print("=== VGX PARAMETERS ===")
        print(f"mode      : {args.mode}")
        print(f"ciphermode: {args.ciphermode}")
        print(f"rounds    : {args.rounds}")
        print(f"weakness  : {args.weakness}")
        print(f"key       : {bytes_to_hex(key8)}")
        print(f"cue(dec)  : {' '.join(str(x) for x in cue8)}")
        print(f"cue(hex)  : {bytes_to_hex(cue8)}")
        if iv is not None:
            print(f"iv        : {bytes_to_hex(iv)}")
        print("subkeys:")
        for i, sk in enumerate(subkeys, start=1):
            print(f"  r{i:02d}: {sk:08X}")
        print("======================")

    if args.mode == "encrypt":
        if not args.plain:
            sys.exit("Missing --plain for encryption.")
        pt = hex_to_bytes(args.plain)

        if args.ciphermode == "ecb":
            ct = ecb_encrypt(pt, subkeys, params)
        elif args.ciphermode == "ofb":
            ct = ofb_crypt(pt, subkeys, params, iv)
        else:  # ctr
            ct = ctr_crypt(pt, subkeys, params, iv)

        print(f"CIPHERTEXT: {bytes_to_hex(ct)}")

    else:  # decrypt
        if not args.cipher:
            sys.exit("Missing --cipher for decryption.")
        ct = hex_to_bytes(args.cipher)

        if args.ciphermode == "ecb":
            pt = ecb_decrypt(ct, subkeys, params)
        elif args.ciphermode == "ofb":
            pt = ofb_crypt(ct, subkeys, params, iv)
        else:  # ctr
            pt = ctr_crypt(ct, subkeys, params, iv)

        print(f"PLAINTEXT : {bytes_to_hex(pt)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
