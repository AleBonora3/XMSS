# params.py
from __future__ import annotations
from dataclasses import dataclass
import math
from utils import lg_w, ceil_div

@dataclass(frozen=True)
class XMSSParams:
    """
    Minimal parameter container for single-tree XMSS (RFC 8391, Section 4.1.1).
    n: bytes
    w: Winternitz parameter (4 or 16)
    h: Merkle tree height (2^h signatures)
    """
    n: int = 32
    w: int = 16
    h: int = 10  # 1024 signatures by default (change for demo!)

    @property
    def len_1(self) -> int:
        # len_1 = ceil(8n / lg(w))
        return math.ceil((8 * self.n) / lg_w(self.w))

    @property
    def len_2(self) -> int:
        # len_2 = floor(lg(len_1*(w-1))/lg(w)) + 1
        logw = lg_w(self.w)
        v = self.len_1 * (self.w - 1)
        return (math.floor(math.log(v, self.w)) if v > 0 else 0) + 1

    @property
    def length(self) -> int:
        return self.len_1 + self.len_2

    @property
    def len_2_bytes(self) -> int:
        # ceil((len_2*lg(w))/8)
        return ceil_div(self.len_2 * lg_w(self.w), 8)

    @property
    def max_signatures(self) -> int:
        return 1 << self.h
