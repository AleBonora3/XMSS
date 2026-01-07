# utils.py
from __future__ import annotations
import math

def to_bytes(x: int, outlen: int) -> bytes:
    """RFC 8391, Section 2.4: big-endian integer-to-byte."""
    if x < 0:
        raise ValueError("x must be non-negative")
    return x.to_bytes(outlen, "big", signed=False)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))

def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b

def lg_w(w: int) -> int:
    # RFC limits w to {4, 16}; log2(w) is integer.
    if w not in (4, 16):
        raise ValueError("w must be 4 or 16")
    return int(math.log2(w))

def base_w(x: bytes, w: int, out_len: int) -> list[int]:
    """
    RFC 8391, Section 2.6 (Algorithm 1): interpret byte-string as base-w digits.
    Works for w in {4,16}.
    """
    logw = lg_w(w)
    total_bits = len(x) * 8
    needed_bits = out_len * logw
    if needed_bits > total_bits:
        raise ValueError("base_w: out_len too large for input length")

    res: list[int] = []
    bits_consumed = 0
    acc = 0
    acc_bits = 0

    for byte in x:
        acc = (acc << 8) | byte
        acc_bits += 8
        while acc_bits >= logw and len(res) < out_len:
            shift = acc_bits - logw
            digit = (acc >> shift) & (w - 1)
            res.append(digit)
            acc_bits -= logw
            acc &= (1 << acc_bits) - 1 if acc_bits > 0 else 0
            bits_consumed += logw

        if len(res) == out_len:
            break

    if len(res) != out_len:
        raise ValueError("base_w: could not extract enough digits")

    return res
