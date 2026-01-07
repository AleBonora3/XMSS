# XMSS (Python)

Implementazione didattica di XMSS (RFC 8391) con WOTS+, L-tree e Merkle tree.
Include una demo interattiva per visualizzare il percorso di autenticazione e
verificare diversi casi di test.

## Requisiti

- Python 3.9+

## Esecuzione demo

Da `xmss_py/`:

```bash
python demo.py
```

La demo:
- genera `sk.bin`, `pk.bin` e `merkle.json`
- avvia un piccolo server HTTP locale
- apre il viewer in browser (`viewer/index.html`)
- mostra test di verifica (firma corretta, messaggio errato, firma corrotta, ecc.)

Premi Invio nel terminale per chiudere il server.

## Uso base

```python
from params import XMSSParams
from xmss import xmss_keygen, xmss_sign, xmss_verify

params = XMSSParams(n=32, w=16, h=4)
sk, pk = xmss_keygen(params)

msg = b"hello"
sk2, sig = xmss_sign(msg, sk)

ok = xmss_verify(sig, msg, pk)
print(ok)  # True
```

Nota: XMSS è stateful. Dopo ogni firma, salva sempre la chiave privata aggiornata
('sk2'), altrimenti rischi di riutilizzare lo stesso indice.

## Struttura del progetto

- `xmss.py`: keygen, sign, verify e treehash (single-tree XMSS)
- `wots.py`: WOTS+ (catene, firma, ricostruzione della PK)
- `ltree.py`: costruzione L-tree e `rand_hash`
- `hashfuncs.py`: PRF/H/F/H_msg (basate su SHA-256/HMAC)
- `serialize.py`: formato binario di chiavi (`sk.bin`, `pk.bin`)
- `merkle_dump.py`: esporta `merkle.json` per il viewer
- `viewer/`: UI per la visualizzazione dell'albero

## Parametri

`XMSSParams` controlla la sicurezza e le dimensioni:
- `n`: byte di sicurezza (default 32)
- `w`: Winternitz (4 o 16)
- `h`: altezza dell'albero (numero firme = 2^h)

## Note

Questo progetto è pensato per studio e dimostrazione. Non è un'implementazione
production-ready: usa con attenzione e non riutilizzare mai uno stesso indice di firma.
