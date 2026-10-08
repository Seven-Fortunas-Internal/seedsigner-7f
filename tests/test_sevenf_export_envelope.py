"""
    Tests for models/sevenf/export_envelope.py: the device's ceremony exports
    carry their final file name and exact file contents, so the host page can
    save them as the files 7fchain's tools expect (Jorge, 2026-10-07: "the QR
    provides the file name").
"""
import hashlib
import json
from pathlib import Path

import pytest

from seedsigner.models.sevenf.export_envelope import (
    ENVELOPE_VERSION,
    der_to_pem,
    pem_to_der,
    root_cert_export,
)

# Written by `sf-wallet-gov sign-root-cert --index 0` (7fchain 416f576) for
# "abandon x23 art", testnet -- the reference for the PEM text format.
GOV_PEM = (Path(__file__).parent / "fixtures" / "sf_wallet_gov_root_cert_abandon_art_testnet.pem").read_text()


def test_pem_matches_sf_wallet_gov_byte_for_byte():
    assert der_to_pem(pem_to_der(GOV_PEM)) == GOV_PEM


def test_pem_shape():
    pem = der_to_pem(bytes(range(256)) * 3)
    lines = pem.splitlines()
    assert lines[0] == "-----BEGIN CERTIFICATE-----" and lines[-1] == "-----END CERTIFICATE-----"
    assert all(len(line) == 64 for line in lines[1:-2]) and 0 < len(lines[-2]) <= 64
    assert pem.endswith("-----END CERTIFICATE-----\n")


def test_pem_to_der_refuses_non_certificate_text():
    with pytest.raises(ValueError):
        pem_to_der("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")


def test_root_cert_export_names_the_file_by_the_subject_ski():
    der = pem_to_der(GOV_PEM)
    from embit.bip39 import mnemonic_to_seed
    from seedsigner.models.sevenf.constants import ChainKind
    from seedsigner.models.sevenf.root_ceremony import derive_root_ceremony_keys
    vk = derive_root_ceremony_keys(mnemonic_to_seed(" ".join(["abandon"] * 23 + ["art"]), password=""), ChainKind.TESTNET).root_ca.public_key

    envelope = json.loads(root_cert_export(der, vk))
    assert envelope == {
        "sf7_export": ENVELOPE_VERSION,
        "kind": "root-cert",
        "file": "root-591c511984a2d73c6bee1f4dc149d48f7f97fc55.pem",
        "body": GOV_PEM,
    }
    assert hashlib.sha256(vk).hexdigest()[:40] == "591c511984a2d73c6bee1f4dc149d48f7f97fc55"


# Written by `sf-wallet-gov sign-genesis --index 0` (7fchain 416f576, the
# 2026-10-07 end-to-end run): serde pretty JSON plus write_out's newline.
GOV_GENESIS = (Path(__file__).parent / "fixtures" / "sf_wallet_gov_sign_genesis_76a2e66c.genesis").read_text()


def test_signature_body_matches_sf_wallet_gov_byte_for_byte():
    from seedsigner.models.sevenf.export_envelope import signature_export
    sig = bytes.fromhex(json.loads(GOV_GENESIS)["sig"])
    vk = b"\x07" * 1952
    env = json.loads(signature_export("genesis", vk, sig))
    assert env["body"] == GOV_GENESIS


@pytest.mark.parametrize("kind, ext", [("genesis", "genesis"), ("devfund", "devfund")])
def test_signature_export_names_the_file_by_the_signer_ski(kind, ext):
    from seedsigner.models.sevenf.export_envelope import signature_export
    vk = b"\x07" * 1952
    env = json.loads(signature_export(kind, vk, b"\x01" * 3309))
    assert env["kind"] == f"{kind}-sig"
    assert env["file"] == f"{hashlib.sha256(vk).hexdigest()[:40]}.{ext}"
    assert json.loads(env["body"]) == {"signer_vk": "", "sig": "01" * 3309}


def test_signature_export_refuses_an_unknown_kind():
    from seedsigner.models.sevenf.export_envelope import signature_export
    with pytest.raises(ValueError):
        signature_export("treasury", b"\x07" * 1952, b"\x01" * 3309)


GOV_DEPUTY = (Path(__file__).parent / "fixtures" / "sf_wallet_gov_deputy_cert_issuer_255ef46a.pem").read_text()


def test_deputy_cert_export_is_named_for_the_issuing_root():
    """ sign-deputy-cert writes deputy-<issuing Root ski>.pem (7fchain ce04ae9:
        named for the ISSUER -- six Roots certify one Deputy). """
    from seedsigner.models.sevenf.export_envelope import deputy_cert_export
    issuer_vk = b"\x09" * 1952
    env = json.loads(deputy_cert_export(pem_to_der(GOV_DEPUTY), issuer_vk))
    assert env["kind"] == "deputy-cert"
    assert env["file"] == f"deputy-{hashlib.sha256(issuer_vk).hexdigest()[:40]}.pem"
    assert env["body"] == GOV_DEPUTY


@pytest.mark.parametrize("role", ["root", "devfund"])
def test_vk_export_is_tagged_with_its_role(role):
    """ The runbook warns a Root vk was once sent as the dev-fund vk; both are
        <ski>.vk, so the export says which key it is. Body exactly as
        sf-wallet-gov writes a .vk: lowercase hex plus a newline. """
    from seedsigner.models.sevenf.export_envelope import vk_export
    vk = b"\x0b" * 1952
    env = json.loads(vk_export(role, vk))
    assert env["kind"] == f"{role}-vk"
    assert env["file"] == f"{hashlib.sha256(vk).hexdigest()[:40]}.vk"
    assert env["body"] == vk.hex() + "\n"


def test_vk_export_refuses_an_unknown_role():
    from seedsigner.models.sevenf.export_envelope import vk_export
    with pytest.raises(ValueError):
        vk_export("treasury", b"\x0b" * 1952)
