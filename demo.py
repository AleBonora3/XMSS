# demo.py
from __future__ import annotations
import os
import socket
import threading
import webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

from params import XMSSParams
from xmss import xmss_keygen, xmss_sign, xmss_verify, xmss_root_from_sig
from address import Address
from utils import to_bytes
from hashfuncs import H_msg
from wots import wots_pk_from_sig
from ltree import ltree, rand_hash
from serialize import save_private_key, load_private_key, save_public_key, load_public_key
from merkle_dump import dump_merkle_json, build_merkle_json


def _find_free_port(start: int = 8000, max_tries: int = 20) -> int:
    for port in range(start, start + max_tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("localhost", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port found")


def _start_server() -> ThreadingHTTPServer:
    port = _find_free_port()
    httpd = ThreadingHTTPServer(("localhost", port), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(f"Viewer: http://localhost:{port}/viewer/index.html")
    webbrowser.open(f"http://localhost:{port}/viewer/index.html")
    return httpd


def _root_from_sig_for_msg(sig: bytes, msg: bytes, PK) -> tuple[bytes, bytes]:
    params = PK.params
    n = params.n
    min_len = 4 + n + (params.length + params.h) * n
    if len(sig) != min_len:
        raise ValueError("Firma con lunghezza non valida")

    idx_sig = int.from_bytes(sig[0:4], "big")
    off = 4
    r = sig[off:off+n]
    off += n

    sig_ots = [sig[off + i*n: off + (i+1)*n] for i in range(params.length)]
    off += params.length * n
    auth = [sig[off + i*n: off + (i+1)*n] for i in range(params.h)]

    adrs = Address()
    Mp_key = r + PK.root + to_bytes(idx_sig, n)
    Mp = H_msg(Mp_key, msg, n)
    root_from_sig = xmss_root_from_sig(idx_sig, sig_ots, auth, Mp, PK.pub_seed, params, adrs)
    return root_from_sig, Mp


def _sig_index(sig: bytes) -> int:
    return int.from_bytes(sig[0:4], "big")


def _auth_path_from_sig(sig: bytes, PK) -> list[dict]:
    params = PK.params
    n = params.n
    min_len = 4 + n + (params.length + params.h) * n
    if len(sig) != min_len:
        raise ValueError("Firma con lunghezza non valida")

    idx_sig = _sig_index(sig)
    off = 4 + n + (params.length * n)
    auth = []
    for k in range(params.h):
        sibling_index = (idx_sig // (1 << k)) ^ 1
        start = off + (k * n)
        sibling_value = sig[start:start + n].hex()
        auth.append(
            {
                "level": k,
                "sibling_index": sibling_index,
                "sibling_value": sibling_value,
            }
        )
    return auth


def _leaf_from_sig_for_msg(sig: bytes, msg: bytes, PK) -> bytes:
    params = PK.params
    n = params.n
    min_len = 4 + n + (params.length + params.h) * n
    if len(sig) != min_len:
        raise ValueError("Firma con lunghezza non valida")

    idx_sig = _sig_index(sig)
    off = 4 + n
    sig_ots = [sig[off + i*n: off + (i+1)*n] for i in range(params.length)]

    adrs = Address()
    Mp_key = sig[4:4+n] + PK.root + to_bytes(idx_sig, n)
    Mp = H_msg(Mp_key, msg, n)

    adrs.set_type(0)
    adrs.set_ots_address(idx_sig)
    pk_ots = wots_pk_from_sig(sig_ots, Mp, PK.pub_seed, adrs, params)

    adrs.set_type(1)
    adrs.set_ltree_address(idx_sig)
    return ltree(pk_ots, PK.pub_seed, adrs, params)


def _auth_nodes_for_msg(sig: bytes, msg: bytes, PK, auth_path: list[dict]) -> list[bytes]:
    params = PK.params
    n = params.n
    min_len = 4 + n + (params.length + params.h) * n
    if len(sig) != min_len:
        raise ValueError("Firma con lunghezza non valida")

    idx_sig = _sig_index(sig)
    node = _leaf_from_sig_for_msg(sig, msg, PK)
    nodes: list[bytes] = []
    adrs = Address()
    idx = idx_sig
    for k in range(params.h):
        sibling = bytes.fromhex(auth_path[k]["sibling_value"])
        adrs.set_type(2)
        adrs.set_tree_height(k)
        if (idx % 2) == 0:
            adrs.set_tree_index(idx // 2)
            node = rand_hash(node, sibling, PK.pub_seed, adrs, params)
        else:
            adrs.set_tree_index((idx - 1) // 2)
            node = rand_hash(sibling, node, PK.pub_seed, adrs, params)
        nodes.append(node)
        idx //= 2
    return nodes

def _flip_first_bit(data: bytes) -> bytes:
    if not data:
        return data
    return bytes([data[0] ^ 0x01]) + data[1:]

def _run_extra_tests(params: XMSSParams) -> dict:
    results: dict[str, object] = {}

    SK, PK = xmss_keygen(params)
    msg = b"test XMSS"
    SK2, sig = xmss_sign(msg, SK)

    # Test base (sign/verify OK, wrong message, corrupted signature) sono nel viewer.

    # Test 4: wrong PK (chiave pubblica diversa).
    _, PK_wrong = xmss_keygen(params)
    results["wrong_pk"] = xmss_verify(sig, msg, PK_wrong)

    # Test 5: signature length (troncata e con byte extra).
    results["sig_truncated"] = xmss_verify(sig[:-1], msg, PK)
    results["sig_extra"] = xmss_verify(sig + b"\x00", msg, PK)

    # Test 6: idx monotono su N firme (deve essere strettamente crescente).
    N = 4
    idxs = []
    SKn = SK2
    for i in range(N):
        SKn, sig_n = xmss_sign(msg + bytes([i]), SKn)
        idxs.append(_sig_index(sig_n))
    results["idx_values"] = idxs
    results["idx_monotonic"] = all(idxs[i] < idxs[i + 1] for i in range(len(idxs) - 1))

    # Test 7: exhaustion (2^h + 1 firme). L'ultima deve lanciare errore.
    SK_exh, _ = xmss_keygen(params)
    exhausted = False
    try:
        for _ in range(params.max_signatures + 1):
            SK_exh, _ = xmss_sign(msg, SK_exh)
    except ValueError:
        exhausted = True
    results["exhaustion_2^h_plus_1"] = exhausted

    # Test 8: rollback demo. Ri-uso SK precedente per firmare -> stesso idx, due firme valide.
    SK_rb, PK_rb = xmss_keygen(params)
    SK_before = SK_rb
    _, sig1 = xmss_sign(b"rollback-1", SK_rb)
    _, sig2 = xmss_sign(b"rollback-2", SK_before)
    results["rollback_same_idx"] = _sig_index(sig1) == _sig_index(sig2)
    results["rollback_sig1_ok"] = xmss_verify(sig1, b"rollback-1", PK_rb)
    results["rollback_sig2_ok"] = xmss_verify(sig2, b"rollback-2", PK_rb)
    results["rollback_idx"] = _sig_index(sig1)

    return results


def _build_demo_payload(sig: bytes, msg: bytes, PK, base: dict | None, label: str, note: str | None = None,
                        extra: dict | None = None) -> dict:
    payload: dict[str, object] = {
        "label": label,
        "msg": msg.decode("utf-8", errors="backslashreplace"),
        "verify": xmss_verify(sig, msg, PK),
    }
    if note:
        payload["note"] = note
    if extra:
        payload.update(extra)

    if base is not None:
        payload.update(
            {
                "params": base["params"],
                "target_idx": base["target_idx"],
                "pub_seed": base["pub_seed"],
                "root": base["root"],
                "tree": base["tree"],
                "auth_path": base["auth_path"],
                "path": base["path"],
            }
        )

    try:
        root_from_sig, mp = _root_from_sig_for_msg(sig, msg, PK)
        leaf_from_sig = _leaf_from_sig_for_msg(sig, msg, PK)
        leaf_expected = base["path"][0]["node_value"] if base is not None else ""
        auth_path_used = _auth_path_from_sig(sig, PK)
        auth_nodes = _auth_nodes_for_msg(sig, msg, PK, auth_path_used)
        payload.update(
            {
                "mp": mp.hex(),
                "leaf_expected": leaf_expected,
                "leaf_from_auth": leaf_from_sig.hex(),
                "leaf_match": leaf_from_sig.hex() == leaf_expected,
                "auth_path_used": auth_path_used,
                "auth_nodes": [{"level": i, "value": n.hex()} for i, n in enumerate(auth_nodes)],
                "root_from_auth": root_from_sig.hex(),
                "root_match": root_from_sig == PK.root,
                "root_expected": PK.root.hex(),
            }
        )
    except ValueError as exc:
        payload["error"] = str(exc)
    return payload


def main() -> None:
    base_dir = os.path.dirname(__file__)
    os.chdir(base_dir)

    params = XMSSParams(n=32, w=16, h=4)
    SK, PK = xmss_keygen(params)
    SK_init = SK

    save_private_key("sk.bin", SK)
    save_public_key("pk.bin", PK)
    msg = b"demo XMSS."

    httpd = _start_server()

    # --- firma ---
    SK = load_private_key("sk.bin")   # simula ripresa da disco
    PK = load_public_key("pk.bin")

    SK2, sig = xmss_sign(msg, SK)
    save_private_key("sk.bin", SK2)   # IMPORTANTISSIMO: salva stato aggiornato

    # Test 1: sign/verify OK. La firma deve verificare con lo stesso messaggio e PK corretta.
    ok = xmss_verify(sig, msg, PK)
    print("verify (OK):", ok)

    # Test 2: wrong message. Verifica con messaggio diverso -> deve fallire.
    neg_msg = xmss_verify(sig, b"msg diverso", PK)
    print("verify wrong msg (NEGATIVO):", neg_msg)

    # Test 3: corrupted signature byte. Corrompe l'ultimo byte della firma (auth_path) -> deve fallire.
    sig_bad = sig[:-1] + bytes([sig[-1] ^ 0x01])
    neg_sig = xmss_verify(sig_bad, msg, PK)
    print("verify corrupted sig (NEGATIVO):", neg_sig)

    target_idx = _sig_index(sig)
    base = build_merkle_json(SK_init, target_idx=target_idx)
    # Demo viewer: tutti i test richiesti come voci nel menu.
    msg_wrong = b"msg diverso"
    msg_flip = _flip_first_bit(msg)
    _, PK_wrong = xmss_keygen(params)
    sig_trunc = sig[:-1]
    sig_extra = sig + b"\x00"

    # Test idx monotono.
    SK_mono, PK_mono = xmss_keygen(params)
    idxs = []
    SKn = SK_mono
    for i in range(4):
        SKn, sig_n = xmss_sign(msg + bytes([i]), SKn)
        idxs.append(_sig_index(sig_n))
    idx_monotonic = all(idxs[i] < idxs[i + 1] for i in range(len(idxs) - 1))

    # Test exhaustion.
    SK_exh, _ = xmss_keygen(params)
    exhausted = False
    try:
        for _ in range(params.max_signatures + 1):
            SK_exh, _ = xmss_sign(msg, SK_exh)
    except ValueError:
        exhausted = True

    # Test rollback.
    SK_rb, PK_rb = xmss_keygen(params)
    SK_before = SK_rb
    _, sig_rb1 = xmss_sign(b"rollback-1", SK_rb)
    _, sig_rb2 = xmss_sign(b"rollback-2", SK_before)
    base_rb = build_merkle_json(SK_rb, target_idx=_sig_index(sig_rb1))

    demos = {
        # I primi tre test rimangono come prima (già verificati nel viewer).
        "ok": _build_demo_payload(sig, msg, PK, base, "Firma corretta"),
        "wrong_msg": _build_demo_payload(sig, msg_wrong, PK, base, "Messaggio diverso"),
        "corrupted_sig": _build_demo_payload(sig_bad, msg, PK, base, "Firma corrotta"),
        # Test aggiuntivi richiesti.
        "wrong_pk": _build_demo_payload(sig, msg, PK_wrong, base, "Wrong PK"),
        "sig_trunc": _build_demo_payload(sig_trunc, msg, PK, base, "Signature length (truncated)"),
        "sig_extra": _build_demo_payload(sig_extra, msg, PK, base, "Signature length (extra byte)"),
        "idx_monotonic": {
            "label": "Idx monotono su N firme",
            "note": "Gli indici devono essere strettamente crescenti.",
            "idx_values": idxs,
            "idx_monotonic": idx_monotonic,
        },
        "exhaustion": {
            "label": "Exhaustion (2^h + 1)",
            "note": "L'ultima firma deve fallire per esaurimento indici.",
            "exhausted": exhausted,
            "max_signatures": params.max_signatures,
        },
        "rollback": _build_demo_payload(
            sig_rb1,
            b"rollback-1",
            PK_rb,
            base_rb,
            "Rollback demo",
            note="Due firme valide con lo stesso idx (vulnerabilita operativa).",
            extra={
                "rollback_sig2_ok": xmss_verify(sig_rb2, b"rollback-2", PK_rb),
                "rollback_same_idx": _sig_index(sig_rb1) == _sig_index(sig_rb2),
                "rollback_idx": _sig_index(sig_rb1),
            },
        ),
    }
    dump_merkle_json("merkle.json", SK_init, target_idx=target_idx, demos=demos)  # salva albero + demo

    print("\n--- extra tests ---")
    extra = _run_extra_tests(params)
    for k, v in extra.items():
        print(f"{k}: {v}")

    input("Premi Invio per chiudere il server...")
    httpd.shutdown()

if __name__ == "__main__":
    main()
