# hashfuncs.py
from __future__ import annotations
import hashlib
import hmac

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def PRF(key_n: bytes, in_32: bytes, n: int) -> bytes:
    if len(key_n) != n:
        raise ValueError("PRF: key length != n")
    # RFC: PRF takes (n-byte key, 32-byte index/address); in our usage address is always 32 bytes.
    return hmac_sha256(key_n, in_32)[:n]

def F(key_n: bytes, x_n: bytes, n: int) -> bytes:
    if len(key_n) != n or len(x_n) != n:
        raise ValueError("F: length mismatch")
    return hmac_sha256(key_n, x_n)[:n]

def H(key_n: bytes, x_2n: bytes, n: int) -> bytes:
    if len(key_n) != n or len(x_2n) != 2 * n:
        raise ValueError("H: length mismatch")
    return hmac_sha256(key_n, x_2n)[:n]

def H_msg(key_3n: bytes, msg: bytes, n: int) -> bytes:
    if len(key_3n) != 3 * n:
        raise ValueError("H_msg: key length != 3n")
    return sha256(key_3n + msg)[:n]
