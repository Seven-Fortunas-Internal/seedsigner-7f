"""
    NIST ACVP conformance for this project's ML-DSA-65 (FIPS 204) usage.

    Two separate claims, each independently checked, because neither one
    alone is sufficient:

    1. The independent verifier (`dilithium-py`) is itself trustworthy --
       checked against 15 official NIST ACVP sigVer test vectors
       (ML-DSA-65, pure/external interface -- this project's exact
       configuration: empty-context signing via mldsa7f's `sign()`/
       `verify()`, never the prehash variant). An unvetted third-party
       crypto library earns no trust just by being independent; it has to
       actually reproduce NIST's own published answers first.
       Source: https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/
       {prompt,expectedResults}.json, tgId 3 (parameterSet=ML-DSA-65,
       preHash=pure, signatureInterface=external), tcIds 31-45, fetched
       2026-09-29. Pinned in tests/fixtures/ rather than fetched at test
       time -- a correctness test should not depend on live network access.

    2. Once the verifier is trusted, it's used to independently confirm a
       *real* mldsa7f-produced signature -- not another self-consistency
       check against the same code that produced it (this file's sibling,
       test_sevenf_mldsa.py, already covers that; this is the different,
       stronger claim: an outside implementation agrees).

    Background: found live 2026-09-29 during the first real hardware pass
    for genesis-config signing -- an early attempt at this exact
    cross-check reported a mismatch. Root cause was a test-harness bug (the
    verifying script recomputed the canonical bytes with a fresh
    `int(time.time())` instead of reusing the actual bytes that were
    signed), not a real signing defect -- but it's exactly the kind of gap
    this project should never have to re-discover by hand again, hence
    this permanent, CI-checked test.
"""
import json
import os

import pytest

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import MASTER_SEED_LEN

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _lib_available(),
    reason="firmware/mldsa7f not built -- run `cargo build --release` in firmware/mldsa7f/ first",
)


def _load_sigver_vectors():
    path = os.path.join(FIXTURES_DIR, "nist_acvp_ml_dsa_65_sigver_pure_external.json")
    with open(path) as f:
        return json.load(f)


def test_dilithium_py_matches_all_nist_acvp_sigver_vectors():
    from dilithium_py.ml_dsa import ML_DSA_65

    vectors = _load_sigver_vectors()
    assert len(vectors) == 15, "fixture file was trimmed or corrupted -- expected all 15 pinned vectors"
    assert sum(1 for v in vectors if v["expected_pass"]) == 3, "expected exactly 3 genuinely-valid vectors"

    for v in vectors:
        pk = bytes.fromhex(v["pk"])
        msg = bytes.fromhex(v["message"])
        sig = bytes.fromhex(v["signature"])
        ctx = bytes.fromhex(v["context"]) if v["context"] else b""
        result = ML_DSA_65.verify(pk, msg, sig, ctx)
        assert result == v["expected_pass"], (
            f"tcId={v['tcId']}: dilithium-py disagrees with NIST's own expected result -- "
            f"do not trust this library for the tests below until this is understood"
        )


def test_real_mldsa7f_signature_independently_verifies():
    """ Sign with the actual on-device code path (mldsa.derive_and_sign, the
        same ctypes bridge every 7F view calls), then confirm a completely
        separate implementation (dilithium-py, already proven NIST-conformant
        above) agrees the signature is valid -- not just that mldsa7f agrees
        with itself. """
    from dilithium_py.ml_dsa import ML_DSA_65

    seed = bytes([0x2A] * MASTER_SEED_LEN)  # same FIXED_SEED as test_sevenf_root_ceremony.py
    message = b"NIST ACVP conformance cross-check -- not a real ceremony artefact"
    pk, sig = mldsa.derive_and_sign(seed, "root/testnet/0/ml-dsa/v1", message)
    assert ML_DSA_65.verify(pk, message, sig), "an independent, NIST-vector-validated verifier rejected a real mldsa7f signature"


def test_tampered_signature_is_correctly_rejected():
    """ The negative-case twin of the test above -- confirms the independent
        verifier actually discriminates valid from invalid, rather than
        trivially returning True for anything. """
    from dilithium_py.ml_dsa import ML_DSA_65

    seed = bytes([0x2A] * MASTER_SEED_LEN)
    message = b"NIST ACVP conformance cross-check -- not a real ceremony artefact"
    pk, sig = mldsa.derive_and_sign(seed, "root/testnet/0/ml-dsa/v1", message)

    tampered_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    assert not ML_DSA_65.verify(pk, message, tampered_sig)

    tampered_message = b"a different message entirely"
    assert not ML_DSA_65.verify(pk, tampered_message, sig)
