# ltree.py
from __future__ import annotations
from typing import List
from params import XMSSParams
from address import Address
from utils import xor_bytes
from hashfuncs import PRF, H

def rand_hash(left: bytes, right: bytes, SEED: bytes, adrs: Address, params: XMSSParams) -> bytes:
    """
    RFC 8391, Algorithm 7: KEY, BM_0, BM_1 da PRF(SEED, ADRS) con keyAndMask=0/1/2.
    Ritorna H(KEY, (LEFT^BM0)||(RIGHT^BM1)).
    """
    n = params.n
    adrs.set_key_and_mask(0)
    KEY = PRF(SEED, adrs.to_bytes(), n)
    adrs.set_key_and_mask(1)
    BM0 = PRF(SEED, adrs.to_bytes(), n)
    adrs.set_key_and_mask(2)
    BM1 = PRF(SEED, adrs.to_bytes(), n)
    return H(KEY, xor_bytes(left, BM0) + xor_bytes(right, BM1), n)

def ltree(pk: List[bytes], SEED: bytes, adrs: Address, params: XMSSParams) -> bytes:
    """RFC 8391, Algorithm 8: costruzione dell'L-tree dalla WOTS PK."""
    nodes = pk[:]  # copia difensiva per non mutare l'input
    l = len(nodes)

    adrs.set_tree_height(0)
    while l > 1:
        for i in range(l // 2):
            adrs.set_tree_index(i)
            nodes[i] = rand_hash(nodes[2*i], nodes[2*i + 1], SEED, adrs, params)
        if l % 2 == 1:
            # Se numero di nodi dispari, l'ultimo viene promosso al livello successivo.
            nodes[l // 2] = nodes[l - 1]
            l = (l // 2) + 1
        else:
            l = l // 2
        # Incrementa l'altezza dell'albero per l'indirizzamento.
        adrs.set_tree_height(adrs.get_tree_height() + 1)

    return nodes[0]
