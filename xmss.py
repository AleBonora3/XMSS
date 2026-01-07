# xmss.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
import os

from params import XMSSParams
from address import Address
from utils import to_bytes
from hashfuncs import PRF, H_msg
from wots import wots_sk_from_seed, wots_gen_pk, wots_sign, wots_pk_from_sig
from ltree import ltree, rand_hash

@dataclass
class XMSSPublicKey:
    root: bytes
    pub_seed: bytes  # SEED (public)
    params: XMSSParams

@dataclass
class XMSSPrivateKey:
    idx: int
    sk_seed: bytes   # S (secret master seed for WOTS seeds)
    sk_prf: bytes    # SK_PRF (secret)
    root: bytes
    pub_seed: bytes  # SEED (public)
    params: XMSSParams

def _get_wots_seed(sk_seed: bytes, i: int, params: XMSSParams) -> bytes:
    """RFC 8391, Section 4.1.11: S_ots[i] = PRF(S, toByte(i,32))."""
    return PRF(sk_seed, to_bytes(i, 32), params.n)

def treehash(SK: XMSSPrivateKey, s: int, t: int, adrs: Address) -> bytes:
    """
    RFC 8391, Algorithm 9 (naive stack-based treehash).
    Returns root of subtree height t with leftmost leaf index s.
    """
    if s % (1 << t) != 0:
        raise ValueError("treehash: s must be leftmost leaf for subtree of height t")

    # Stack di (nodo, altezza) per combinare i nodi quando hanno la stessa altezza.
    stack: List[Tuple[bytes, int]] = []
    params = SK.params

    for i in range(1 << t):
        SEED = SK.pub_seed

        # OTS PK -> foglia via L-tree.
        adrs.set_type(0)
        adrs.set_ots_address(s + i)
        S_ots = _get_wots_seed(SK.sk_seed, s + i, params)
        wots_sk = wots_sk_from_seed(S_ots, params)
        pk = wots_gen_pk(wots_sk, SEED, adrs, params)

        adrs.set_type(1)
        adrs.set_ltree_address(s + i)
        node = ltree(pk, SEED, adrs, params)

        # Hash nel Merkle tree principale.
        adrs.set_type(2)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i + s)

        node_h = 0
        while stack and stack[-1][1] == node_h:
            left, _h = stack.pop()
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node = rand_hash(left, node, SEED, adrs, params)
            node_h += 1
            adrs.set_tree_height(adrs.get_tree_height() + 1)

        stack.append((node, node_h))

    if len(stack) != 1:
        raise RuntimeError("treehash: stack ended in unexpected state")
    return stack[0][0]

def build_auth(SK: XMSSPrivateKey, i: int, adrs: Address) -> List[bytes]:
    """
    RFC 8391 Section 4.1.9 example buildAuth (very inefficient):
      auth[j] = treehash(SK, k*2^j, j, ADRS), where k=floor(i/2^j) XOR 1
    """
    auth: List[bytes] = []
    h = SK.params.h
    for j in range(h):
        # Indice del nodo "fratello" al livello j.
        k = (i // (1 << j)) ^ 1
        auth.append(treehash(SK, k * (1 << j), j, adrs))
    return auth

def xmss_keygen(params: XMSSParams) -> Tuple[XMSSPrivateKey, XMSSPublicKey]:
    """
    RFC 8391, Algorithm 10 (but with pseudo-random WOTS keys using SK.sk_seed).
    SK stores idx, sk_seed, sk_prf, root, pub_seed.
    """
    n = params.n
    idx = 0
    sk_seed = os.urandom(n)   # secret S
    sk_prf = os.urandom(n)    # secret SK_PRF
    pub_seed = os.urandom(n)  # public SEED

    SK_tmp = XMSSPrivateKey(idx=idx, sk_seed=sk_seed, sk_prf=sk_prf, root=b"\x00"*n, pub_seed=pub_seed, params=params)
    adrs = Address()  # all zeros
    root = treehash(SK_tmp, 0, params.h, adrs)

    SK = XMSSPrivateKey(idx=idx, sk_seed=sk_seed, sk_prf=sk_prf, root=root, pub_seed=pub_seed, params=params)
    PK = XMSSPublicKey(root=root, pub_seed=pub_seed, params=params)
    return SK, PK

def tree_sig(Mp: bytes, SK: XMSSPrivateKey, idx_sig: int, adrs: Address) -> Tuple[List[bytes], List[bytes]]:
    """RFC 8391, Algorithm 11: returns (sig_ots, auth)."""
    # Costruisce il percorso di autenticazione e la firma WOTS+.
    auth = build_auth(SK, idx_sig, adrs)

    adrs.set_type(0)
    adrs.set_ots_address(idx_sig)
    S_ots = _get_wots_seed(SK.sk_seed, idx_sig, SK.params)
    wots_sk = wots_sk_from_seed(S_ots, SK.params)
    sig_ots = wots_sign(Mp, wots_sk, SK.pub_seed, adrs, SK.params)

    return sig_ots, auth

def xmss_sign(M: bytes, SK: XMSSPrivateKey) -> Tuple[XMSSPrivateKey, bytes]:
    """
    RFC 8391, Algorithm 12:
      idx_sig = idx; idx++
      r = PRF(SK_PRF, toByte(idx_sig,32))
      M' = H_msg(r || root || toByte(idx_sig,n), M)
      Sig = idx_sig(4) || r || sig_ots || auth
    """
    params = SK.params
    if SK.idx >= params.max_signatures:
        raise ValueError("XMSS: no signatures left for this key (idx exhausted)")

    idx_sig = SK.idx

    # Aggiorna idx prima di restituire la firma (sicurezza stateful).
    SK2 = XMSSPrivateKey(
        idx=SK.idx + 1,
        sk_seed=SK.sk_seed,
        sk_prf=SK.sk_prf,
        root=SK.root,
        pub_seed=SK.pub_seed,
        params=params,
    )

    adrs = Address()
    r = PRF(SK.sk_prf, to_bytes(idx_sig, 32), params.n)
    Mp_key = r + SK.root + to_bytes(idx_sig, params.n)
    Mp = H_msg(Mp_key, M, params.n)

    sig_ots, auth = tree_sig(Mp, SK, idx_sig, adrs)

    sig_bytes = (
        to_bytes(idx_sig, 4)
        + r
        + b"".join(sig_ots)
        + b"".join(auth)
    )
    return SK2, sig_bytes

def xmss_root_from_sig(idx_sig: int, sig_ots: List[bytes], auth: List[bytes],
                       Mp: bytes, pub_seed: bytes, params: XMSSParams, adrs: Address) -> bytes:
    """RFC 8391, Algorithm 13."""
    # Ricostruisce la root partendo da sig_ots e auth.
    adrs.set_type(0)
    adrs.set_ots_address(idx_sig)
    pk_ots = wots_pk_from_sig(sig_ots, Mp, pub_seed, adrs, params)

    adrs.set_type(1)
    adrs.set_ltree_address(idx_sig)
    node0 = ltree(pk_ots, pub_seed, adrs, params)

    adrs.set_type(2)
    adrs.set_tree_index(idx_sig)

    node = node0
    for k in range(params.h):
        adrs.set_tree_height(k)
        if ((idx_sig // (1 << k)) % 2) == 0:
            # Nodo corrente a sinistra, auth[k] a destra.
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            node = rand_hash(node, auth[k], pub_seed, adrs, params)
        else:
            # Nodo corrente a destra, auth[k] a sinistra.
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node = rand_hash(auth[k], node, pub_seed, adrs, params)
    return node

def xmss_verify(sig: bytes, M: bytes, PK: XMSSPublicKey) -> bool:
    """
    RFC 8391, Algorithm 14.
    Parse signature:
      idx(4) || r(n) || sig_ots(len*n) || auth(h*n)
    """
    params = PK.params
    n = params.n

    # Verifica che la lunghezza della firma sia esattamente quella attesa.
    min_len = 4 + n + (params.length + params.h) * n
    if len(sig) != min_len:
        return False

    idx_sig = int.from_bytes(sig[0:4], "big")
    off = 4
    r = sig[off:off+n]
    off += n

    # Estrae i blocchi di firma WOTS+ e il percorso di autenticazione.
    sig_ots = [sig[off + i*n: off + (i+1)*n] for i in range(params.length)]
    off += params.length * n

    auth = [sig[off + i*n: off + (i+1)*n] for i in range(params.h)]

    adrs = Address()
    Mp_key = r + PK.root + to_bytes(idx_sig, n)
    Mp = H_msg(Mp_key, M, n)

    node = xmss_root_from_sig(idx_sig, sig_ots, auth, Mp, PK.pub_seed, params, adrs)
    return node == PK.root
