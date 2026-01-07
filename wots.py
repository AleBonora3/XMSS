# wots.py
from __future__ import annotations
from typing import List
from params import XMSSParams
from address import Address
from utils import base_w, to_bytes, xor_bytes
from hashfuncs import PRF, F

def wots_sk_from_seed(S_ots: bytes, params: XMSSParams) -> List[bytes]:
    """
    RFC 8391, Section 3.1.7: sk[i] = PRF(S, toByte(i,32)).
    Here S_ots is the secret seed for this specific WOTS keypair.
    """
    n = params.n
    if len(S_ots) != n:
        raise ValueError("S_ots must be n bytes")
    sk: List[bytes] = []
    for i in range(params.length):
        sk.append(PRF(S_ots, to_bytes(i, 32), n))
    return sk

def chain(X: bytes, i: int, s: int, SEED: bytes, adrs: Address, params: XMSSParams) -> bytes:
    """
    RFC 8391, Algorithm 2: chaining function with PRF-derived KEY and BM (bitmask).
    adrs is mutated in the last words only (hash addr + keyAndMask).
    Algoritmo 2: chain – Chaining Function
    Input: stringa X, indice iniziale i, numero di passi s, seed SEED, indirizzo ADRS
    Output: valore ottenuto iterando F s volte su X

    if (s == 0) {
    return X;
    }
    if ((i + s) > (w - 1)) {
    return NULL;
    }
    byte[n] tmp = chain(X, i, s - 1, SEED, ADRS);

    ADRS.setHashAddress(i + s - 1);
    ADRS.setKeyAndMask(0);
    KEY = PRF(SEED, ADRS);
    ADRS.setKeyAndMask(1);
    BM = PRF(SEED, ADRS);

    tmp = F(KEY, tmp XOR BM);
    return tmp;
    """
    n, w = params.n, params.w
    if s == 0:
        return X
    if (i + s) > (w - 1):
        raise ValueError("chain: i+s out of range")

    # Avanza lungo la chain dalla posizione i per s passi.
    tmp = X
    for j in range(i, i + s):
        adrs.set_hash_address(j)
        adrs.set_key_and_mask(0)
        KEY = PRF(SEED, adrs.to_bytes(), n)
        adrs.set_key_and_mask(1)
        BM = PRF(SEED, adrs.to_bytes(), n)
        tmp = F(KEY, xor_bytes(tmp, BM), n)

    return tmp

def wots_gen_pk(sk: List[bytes], SEED: bytes, adrs: Address, params: XMSSParams) -> List[bytes]:
    """RFC 8391, Algorithm 4. Section 3.1.4.
    Algoritmo 4: WOTS_genPK – Generazione della chiave pubblica WOTS+
    Input: chiave privata WOTS+ sk, indirizzo ADRS, seed SEED
    Output: chiave pubblica WOTS+ pk

    for (i = 0; i < len; i++) {
    ADRS.setChainAddress(i);
    pk[i] = chain(sk[i], 0, w - 1, SEED, ADRS);
    }
    return pk;
    """
    # Ogni chain viene portata fino in fondo per ottenere un elemento di PK.
    pk: List[bytes] = []
    for i in range(params.length):
        adrs.set_chain_address(i)
        pk.append(chain(sk[i], 0, params.w - 1, SEED, adrs, params))
    return pk

def _wots_msg_digits(M: bytes, params: XMSSParams) -> List[int]:
    """
    RFC 8391, Algorithms 5/6: base_w(M, len_1) + checksum base_w(..., len_2)
    M must be n bytes (XMSS signs digest M').
    """
    if len(M) != params.n:
        raise ValueError("WOTS expects n-byte message digest")
    w = params.w
    # Converte il digest in cifre base-w (len_1) e aggiunge il checksum (len_2).
    msg = base_w(M, w, params.len_1)

    csum = 0
    for i in range(params.len_1):
        csum += (w - 1) - msg[i]

    # Shift a sinistra del checksum per allinearlo alla codifica base-w.
    shift = 8 - ((params.len_2 * (params.w.bit_length() - 1)) % 8)
    if shift != 8:
        csum = csum << shift

    csum_bytes = to_bytes(csum, params.len_2_bytes)
    msg = msg + base_w(csum_bytes, w, params.len_2)
    if len(msg) != params.length:
        raise RuntimeError("msg digit length mismatch")
    return msg

def wots_sign(M: bytes, sk: List[bytes], SEED: bytes, adrs: Address, params: XMSSParams) -> List[bytes]:
    """RFC 8391, Algorithm 5. Generazione della firma WOTS+"""
    # Usa le cifre base-w per decidere quanto avanzare su ogni chain.
    msg = _wots_msg_digits(M, params)
    sig: List[bytes] = []
    for i in range(params.length):
        adrs.set_chain_address(i)
        sig.append(chain(sk[i], 0, msg[i], SEED, adrs, params))
    return sig

def wots_pk_from_sig(sig: List[bytes], M: bytes, SEED: bytes, adrs: Address, params: XMSSParams) -> List[bytes]:
    """RFC 8391, Algorithm 6."""
    if len(sig) != params.length:
        raise ValueError("sig length mismatch")
    # Completa ogni chain dalla posizione della firma fino alla fine.
    msg = _wots_msg_digits(M, params)
    pk: List[bytes] = []
    for i in range(params.length):
        adrs.set_chain_address(i)
        pk.append(chain(sig[i], msg[i], (params.w - 1) - msg[i], SEED, adrs, params))
    return pk
