# merkle_dump.py
from __future__ import annotations
import json
from typing import Dict, List

from address import Address
from hashfuncs import PRF, H
from ltree import ltree, rand_hash
from params import XMSSParams
from utils import to_bytes, xor_bytes
from wots import wots_gen_pk, wots_sk_from_seed
from xmss import XMSSPrivateKey


def _hex(b: bytes) -> str:
    return b.hex()


def _leaf_from_sk(sk_seed: bytes, pub_seed: bytes, idx: int, params: XMSSParams) -> bytes:
    adrs = Address()
    adrs.set_type(0)
    adrs.set_ots_address(idx)
    s_ots = PRF(sk_seed, to_bytes(idx, 32), params.n)
    wots_sk = wots_sk_from_seed(s_ots, params)
    pk = wots_gen_pk(wots_sk, pub_seed, adrs, params)

    adrs.set_type(1)
    adrs.set_ltree_address(idx)
    return ltree(pk, pub_seed, adrs, params)


def _internal_node_detail(left: bytes, right: bytes, height: int, index: int, pub_seed: bytes, params: XMSSParams) -> Dict[str, str]:
    adrs = Address()
    adrs.set_type(2)
    adrs.set_tree_height(height)
    adrs.set_tree_index(index)

    adrs.set_key_and_mask(0)
    key = PRF(pub_seed, adrs.to_bytes(), params.n)
    adrs.set_key_and_mask(1)
    bm0 = PRF(pub_seed, adrs.to_bytes(), params.n)
    adrs.set_key_and_mask(2)
    bm1 = PRF(pub_seed, adrs.to_bytes(), params.n)

    masked_left = xor_bytes(left, bm0)
    masked_right = xor_bytes(right, bm1)
    node = H(key, masked_left + masked_right, params.n)

    return {
        "index": index,
        "left_index": index * 2,
        "right_index": index * 2 + 1,
        "key": _hex(key),
        "bm0": _hex(bm0),
        "bm1": _hex(bm1),
        "masked_left": _hex(masked_left),
        "masked_right": _hex(masked_right),
        "value": _hex(node),
    }


def build_merkle_json(sk: XMSSPrivateKey, target_idx: int) -> Dict[str, object]:
    params = sk.params
    leaf_count = 1 << params.h

    # Livello foglie.
    leaves: List[bytes] = []
    leaf_nodes: List[Dict[str, str]] = []
    for i in range(leaf_count):
        leaf = _leaf_from_sk(sk.sk_seed, sk.pub_seed, i, params)
        leaves.append(leaf)
        leaf_nodes.append({"index": i, "value": _hex(leaf)})

    levels: List[Dict[str, object]] = [{"level": 0, "nodes": leaf_nodes}]

    # Livelli interni.
    current = leaves
    for height in range(params.h):
        next_nodes: List[bytes] = []
        details: List[Dict[str, str]] = []
        for i in range(0, len(current), 2):
            detail = _internal_node_detail(current[i], current[i + 1], height, i // 2, sk.pub_seed, params)
            next_nodes.append(bytes.fromhex(detail["value"]))
            details.append(detail)
        levels.append({"level": height + 1, "tree_height": height, "nodes": details})
        current = next_nodes

    root = current[0]

    # Auth path e percorso per target_idx.
    auth: List[Dict[str, str]] = []
    path: List[Dict[str, str]] = []
    idx = target_idx
    for level in range(params.h):
        nodes = levels[level]["nodes"]
        node_value = nodes[idx]["value"]
        path.append({"level": level, "node_index": idx, "node_value": node_value})
        sib = idx ^ 1
        auth.append({"level": level, "sibling_index": sib, "sibling_value": nodes[sib]["value"]})
        idx //= 2

    return {
        "params": {"n": params.n, "w": params.w, "h": params.h},
        "target_idx": target_idx,
        "pub_seed": _hex(sk.pub_seed),
        "root": _hex(root),
        "tree": {"levels": levels},
        "auth_path": auth,
        "path": path,
    }


def dump_merkle_json(path: str, sk: XMSSPrivateKey, target_idx: int = 5, demos: Dict[str, object] | None = None) -> None:
    base = build_merkle_json(sk, target_idx)
    payload = {
        "params": base["params"],
        "target_idx": base["target_idx"],
        "pub_seed": base["pub_seed"],
        "root": base["root"],
    }
    if demos is not None:
        payload["demos"] = demos
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
