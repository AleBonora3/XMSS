# address.py
from __future__ import annotations
from dataclasses import dataclass
from utils import to_bytes

@dataclass
class Address:
    """
    RFC 8391, Section 2.5: 32-byte address = 8 words (32-bit each).
    Layout:
      word0: layer (32)
      word1-2: tree (64)
      word3: type (0 OTS, 1 L-tree, 2 hash tree)
      word4-7: depend on type, plus keyAndMask at word7
    """
    w: list[int]

    def __init__(self) -> None:
        self.w = [0] * 8

    def copy(self) -> "Address":
        a = Address()
        a.w = self.w[:]
        return a

    def to_bytes(self) -> bytes:
        out = b""
        for x in self.w:
            out += to_bytes(x & 0xFFFFFFFF, 4)
        return out

    # Common fields
    def set_layer(self, layer: int) -> None:
        self.w[0] = layer & 0xFFFFFFFF

    def set_tree(self, tree: int) -> None:
        tree &= (1 << 64) - 1
        self.w[1] = (tree >> 32) & 0xFFFFFFFF
        self.w[2] = tree & 0xFFFFFFFF

    def set_type(self, t: int) -> None:
        # RFC: when type changes, clear following words to 0
        self.w[3] = t & 0xFFFFFFFF
        for i in range(4, 8):
            self.w[i] = 0

    def set_key_and_mask(self, km: int) -> None:
        self.w[7] = km & 0xFFFFFFFF

    # OTS address (type=0)
    def set_ots_address(self, ots: int) -> None:
        self.w[4] = ots & 0xFFFFFFFF

    def set_chain_address(self, chain: int) -> None:
        self.w[5] = chain & 0xFFFFFFFF

    def set_hash_address(self, ha: int) -> None:
        self.w[6] = ha & 0xFFFFFFFF

    # L-tree address (type=1)
    def set_ltree_address(self, l: int) -> None:
        self.w[4] = l & 0xFFFFFFFF

    def set_tree_height(self, th: int) -> None:
        self.w[5] = th & 0xFFFFFFFF

    def get_tree_height(self) -> int:
        return self.w[5]

    def set_tree_index(self, ti: int) -> None:
        self.w[6] = ti & 0xFFFFFFFF

    def get_tree_index(self) -> int:
        return self.w[6]
