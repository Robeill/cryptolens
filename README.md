# CryptoLens

Static analysis for Python that finds cryptographic usage, works out **what it is for**, and
says what has to be replaced before quantum computers arrive. Outputs a developer report, a
CycloneDX 1.6 CBOM, and purpose-keyed post-quantum migration guidance.

## Why purpose matters

```
ecdsa_sign.py:14   ECDSA   digital_signature   scheduled   ->  ML-DSA-65
ecdsa_sign.py:30   ECDH    key_establishment   urgent      ->  ML-KEM-768
```

Same file, same curve, same mathematics. Traffic protected by the key exchange can be recorded
today and decrypted later, so the exposure has already begun; a signature can only be forged
once the attacker has a quantum computer. A table mapping `RSA -> ML-KEM` is wrong, because RSA
does two unrelated jobs and the replacements are different kinds of primitive.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # Python 3.10+
pip install -e ".[pqc]"     # optional: real PQC key and signature sizes from liboqs
```

## Use

```bash
cryptolens scan .
cryptolens scan . --format cbom --output cbom.json
cryptolens scan . --fail-on high      # exit 1 if anything reaches HIGH
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` the scan could not start.

## Output

```
SUMMARY
  risk      critical=4  high=13  medium=9  low=12  info=13
  priority  immediate=12  urgent=7  scheduled=6  monitor=13  none=13
  quantum   quantum_vulnerable=17  quantum_safe=13  needs_review=21
  totals    51 findings in 33 distinct assets

WHAT TO DO FIRST
  IMMEDIATE (12) -- broken today, or will outlive the 2035 deadline
    auth/passwords.py:24               SHA-1 (hashing)
    legacy/compat.py:21                AES ECB (encryption)
    transport/tls.py:19                TLS-unverified (key_establishment)

  URGENT (7) -- harvest now, decrypt later -- the exposure has already begun
    transport/handshake.py:21          ECDH (key_establishment)

FINDINGS
  CRITICAL (4)
    transport/tls.py
      line 19    TLS-unverified (key_establishment)  [immediate, confidence 1.00]
        - Signature or certificate verification is switched off here, which removes the
          guarantee the algorithm was chosen to provide.
        -> replace with ML-KEM-768 (alternatives: HQC-192) -- Lattice KEM standardised in
           FIPS 203 and the de facto default for TLS.
```

## Results

Held-out set of 15 modules and 363 lines. Ground truth was written and committed before the
scanner was run against it, and the matching rules were frozen before any scoring code
existed. The samples were written from library documentation, but not by someone who had
never seen the detector rules, so treat this as a demonstration rather than a benchmark.

| | Precision | Recall | F1 |
|---|---|---|---|
| CryptoLens, call-site | 0.836 | 0.773 | 0.803 |
| CryptoLens, file-level | 0.895 | 0.895 | 0.895 |
| Bandit, same ground truth | 0.842 | 0.242 | 0.377 |
| Bandit, its own remit | 0.684 | 0.650 | 0.667 |

Bandit is competitive on weak-algorithm detection and attempts no inventory, purpose or quantum
exposure. 13,868 lines of the `cryptography` library scan in 176 ms.

The matching rules are in [`tools/PROTOCOL.md`](tools/PROTOCOL.md), frozen before any scoring
code was written; the raw run records are in [`evaluation/`](evaluation/).

## Limitations

- **No interprocedural data flow.** `private_key.sign(msg)` where the key is a parameter is
  invisible. 6 of 15 misses on the evaluation set — the largest single gap.
- **No purpose awareness without data flow.** `hashlib.md5` used as an ETag is graded HIGH.
  3 of 3 failures, and Bandit fails identically, so this is a limit of the approach.
- **Confidence records how a symbol was resolved, not whether a finding is correct.**
  Precision falls from 0.836 to 0.818 as the confidence floor rises.
- **Dynamic names** (`getattr`, `eval`, `importlib`) are reported at low confidence or not
  at all.
- **Python only.** The detector rules, OID table, PQC catalog and CBOM generator are
  language-independent and would be reused; the analyser is not.

## Tests

```bash
pytest                    # 750 tests, 97% coverage
ruff check src tests tools
```
