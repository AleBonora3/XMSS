# serialize.py
from __future__ import annotations
from dataclasses import asdict
import struct
from params import XMSSParams
from xmss import XMSSPrivateKey, XMSSPublicKey

# Format:
#  - magic 4B: b"XMSS"
#  - version u8
#  - n u16, w u16, h u16
#  - for PK: root(n) || pub_seed(n)
#  - for SK: idx u32 || sk_seed(n) || sk_prf(n) || root(n) || pub_seed(n)

MAGIC = b"XMSS"
VERSION = 1

def save_public_key(path: str, pk: XMSSPublicKey) -> None:
    p = pk.params
    header = MAGIC + struct.pack(">BHHH", VERSION, p.n, p.w, p.h)
    body = pk.root + pk.pub_seed
    with open(path, "wb") as f:
        f.write(header + body)

def load_public_key(path: str) -> XMSSPublicKey:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != MAGIC:
        raise ValueError("Bad magic")
    ver, n, w, h = struct.unpack(">BHHH", data[4:11])
    if ver != VERSION:
        raise ValueError("Unsupported version")
    params = XMSSParams(n=n, w=w, h=h)
    off = 11
    root = data[off:off+n]; off += n
    pub_seed = data[off:off+n]; off += n
    if off != len(data):
        raise ValueError("Trailing bytes")
    return XMSSPublicKey(root=root, pub_seed=pub_seed, params=params)

def save_private_key(path: str, sk: XMSSPrivateKey) -> None:
    p = sk.params
    header = MAGIC + struct.pack(">BHHH", VERSION, p.n, p.w, p.h)
    body = struct.pack(">I", sk.idx) + sk.sk_seed + sk.sk_prf + sk.root + sk.pub_seed
    with open(path, "wb") as f:
        f.write(header + body)

def load_private_key(path: str) -> XMSSPrivateKey:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != MAGIC:
        raise ValueError("Bad magic")
    ver, n, w, h = struct.unpack(">BHHH", data[4:11])
    if ver != VERSION:
        raise ValueError("Unsupported version")
    params = XMSSParams(n=n, w=w, h=h)
    off = 11
    idx = struct.unpack(">I", data[off:off+4])[0]; off += 4
    sk_seed = data[off:off+n]; off += n
    sk_prf  = data[off:off+n]; off += n
    root    = data[off:off+n]; off += n
    pub_seed= data[off:off+n]; off += n
    if off != len(data):
        raise ValueError("Trailing bytes")
    return XMSSPrivateKey(idx=idx, sk_seed=sk_seed, sk_prf=sk_prf, root=root, pub_seed=pub_seed, params=params)
