"""
    Tests seedsigner.models.sevenf.cert_request -- CertRequest JSON parsing/
    validation, and the ctypes bridge to firmware/mldsa7f's Root/Deputy TBS-
    building functions. Backs 7f-signing-support-x509-cert-request-foundation.

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import json

import pytest

from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.cert_request import (
    CERT_REQUEST_VERSION,
    ROLE_DEPUTY,
    ROLE_ROOT,
    CertRequestError,
    CertRequestFields,
    build_deputy_tbs,
    build_root_tbs,
    deputy_tbs_from_request,
    parse_cert_request_json,
    review_fields,
    root_tbs_from_request,
    subject_matches,
)


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

ROOT_VK = bytes([0xAB]) * 1952
DEPUTY_VK = bytes([0xCD]) * 1952
SERIAL = bytes([0x11]) * 16
NOW = 1_700_000_000
DAYS = 3650


def _sample_request_dict(**overrides) -> dict:
    base = dict(
        version=CERT_REQUEST_VERSION,
        kind="testnet",
        role=ROLE_ROOT,
        subject_vk=ROOT_VK.hex(),
        not_before=NOW,
        days=DAYS,
        serial=SERIAL.hex(),
    )
    base.update(overrides)
    return base


# --- parse_cert_request_json ---

def test_parses_a_well_formed_root_request():
    req = parse_cert_request_json(json.dumps(_sample_request_dict()).encode("utf-8"))
    assert req == CertRequestFields(
        version=CERT_REQUEST_VERSION, kind=ChainKind.TESTNET, role=ROLE_ROOT,
        subject_vk=ROOT_VK, not_before=NOW, days=DAYS, serial=SERIAL,
    )


def test_parses_a_well_formed_deputy_request():
    req = parse_cert_request_json(json.dumps(_sample_request_dict(role=ROLE_DEPUTY, subject_vk=DEPUTY_VK.hex())).encode("utf-8"))
    assert req.role == ROLE_DEPUTY
    assert req.subject_vk == DEPUTY_VK


@pytest.mark.parametrize("kind_str,expected", [("mainnet", ChainKind.MAINNET), ("testnet", ChainKind.TESTNET), ("devnet", ChainKind.DEVNET)])
def test_parses_every_chain_kind(kind_str, expected):
    req = parse_cert_request_json(json.dumps(_sample_request_dict(kind=kind_str)).encode("utf-8"))
    assert req.kind == expected


def test_rejects_invalid_json():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(b"not json at all {{{")


def test_rejects_a_json_array_instead_of_object():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(b"[1, 2, 3]")


def test_rejects_wrong_version():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(version=2)).encode("utf-8"))


def test_rejects_unknown_role():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(role="centcom")).encode("utf-8"))


def test_rejects_unknown_chain_kind():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(kind="regtest")).encode("utf-8"))


def test_rejects_non_hex_subject_vk():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(subject_vk="not-hex!!")).encode("utf-8"))


def test_rejects_wrong_length_subject_vk():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(subject_vk="ab" * 100)).encode("utf-8"))


def test_rejects_negative_not_before():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(not_before=-1)).encode("utf-8"))


def test_rejects_zero_days():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(days=0)).encode("utf-8"))


def test_rejects_negative_days():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(days=-5)).encode("utf-8"))


def test_rejects_non_hex_serial():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(serial="zz")).encode("utf-8"))


def test_rejects_oversized_serial():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(serial="11" * 21)).encode("utf-8"))


def test_rejects_negative_serial():
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(serial="80" + "11" * 15)).encode("utf-8"))


def test_rejects_missing_field():
    d = _sample_request_dict()
    del d["days"]
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(d).encode("utf-8"))


def test_rejects_boolean_masquerading_as_int_for_days():
    # bool is an int subclass in Python -- True/False must not slip through
    # an isinstance(x, int) check meant for a real day count.
    with pytest.raises(CertRequestError):
        parse_cert_request_json(json.dumps(_sample_request_dict(days=True)).encode("utf-8"))


# --- subject_matches ---

def test_subject_matches_true_for_the_same_key():
    req = parse_cert_request_json(json.dumps(_sample_request_dict()).encode("utf-8"))
    assert subject_matches(req, ROOT_VK) is True


def test_subject_matches_false_for_a_different_key():
    req = parse_cert_request_json(json.dumps(_sample_request_dict()).encode("utf-8"))
    assert subject_matches(req, DEPUTY_VK) is False


# --- FFI: build_root_tbs / build_deputy_tbs ---

def test_build_root_tbs_is_deterministic():
    a = build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)
    b = build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)
    assert a == b
    assert len(a) > 0


def test_build_root_tbs_differs_by_chain_kind():
    testnet = build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)
    mainnet = build_root_tbs(ROOT_VK, ChainKind.MAINNET, NOW, DAYS, SERIAL)
    assert testnet != mainnet


def test_build_root_tbs_rejects_a_malformed_subject_key():
    with pytest.raises(CertRequestError):
        build_root_tbs(bytes([0xAB]) * 10, ChainKind.TESTNET, NOW, DAYS, SERIAL)


def test_build_deputy_tbs_is_deterministic():
    a = build_deputy_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, DEPUTY_VK, NOW, DAYS, SERIAL)
    b = build_deputy_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, DEPUTY_VK, NOW, DAYS, SERIAL)
    assert a == b
    assert len(a) > 0


def test_build_deputy_tbs_rejects_a_window_outside_the_roots_own():
    with pytest.raises(CertRequestError):
        build_deputy_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, DEPUTY_VK, NOW - 1, DAYS, SERIAL)


def test_root_and_deputy_tbs_are_never_equal_for_distinct_subjects():
    root = build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)
    deputy = build_deputy_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, DEPUTY_VK, NOW, DAYS, SERIAL)
    assert root != deputy


# --- root_tbs_from_request / deputy_tbs_from_request ---

def test_root_tbs_from_request_matches_build_root_tbs_directly():
    req = parse_cert_request_json(json.dumps(_sample_request_dict()).encode("utf-8"))
    assert root_tbs_from_request(req) == build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)


def test_root_tbs_from_request_refuses_a_deputy_request():
    req = parse_cert_request_json(json.dumps(_sample_request_dict(role=ROLE_DEPUTY, subject_vk=DEPUTY_VK.hex())).encode("utf-8"))
    with pytest.raises(CertRequestError):
        root_tbs_from_request(req)


def test_deputy_tbs_from_request_matches_build_deputy_tbs_directly():
    req = parse_cert_request_json(json.dumps(_sample_request_dict(role=ROLE_DEPUTY, subject_vk=DEPUTY_VK.hex())).encode("utf-8"))
    got = deputy_tbs_from_request(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, req)
    assert got == build_deputy_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, DEPUTY_VK, NOW, DAYS, SERIAL)


def test_deputy_tbs_from_request_refuses_a_root_request():
    req = parse_cert_request_json(json.dumps(_sample_request_dict()).encode("utf-8"))
    with pytest.raises(CertRequestError):
        deputy_tbs_from_request(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, req)


# --- review_fields: the no-blind-signing screen content ---

def test_review_fields_includes_role_subject_kind_dates_and_serial():
    req = parse_cert_request_json(json.dumps(_sample_request_dict()).encode("utf-8"))
    fields = review_fields(req)
    assert all(isinstance(f, ReviewField) for f in fields)
    labels = [f.label for f in fields]
    assert labels == ["Role", "Subject key id", "Chain", "Valid from", "Valid for", "Serial"]

    by_label = {f.label: f.value for f in fields}
    assert by_label["Role"] == ROLE_ROOT
    assert by_label["Chain"] == "testnet"
    assert by_label["Valid for"] == f"{DAYS} days"
    assert by_label["Serial"] == SERIAL.hex()
    assert str(NOW) in by_label["Valid from"]  # raw value shown, per genesis-config's own _format_timestamp


def test_review_fields_serial_differs_for_a_coordinator_rerun_with_a_new_timestamp():
    """ Two requests that otherwise look "the same" (role/subject/kind) but
        came from separate prepare-root-cert runs get different serials
        (CertRequest's serial is SHA256(role||subject_vk||now||days)) -- the
        review screen must show that difference, not hide it. Confirms the
        MEDIUM finding from adversarial review is closed by construction. """
    req1 = parse_cert_request_json(json.dumps(_sample_request_dict(serial="11" * 16)).encode("utf-8"))
    req2 = parse_cert_request_json(json.dumps(_sample_request_dict(serial="22" * 16)).encode("utf-8"))
    by_label_1 = {f.label: f.value for f in review_fields(req1)}
    by_label_2 = {f.label: f.value for f in review_fields(req2)}
    assert by_label_1["Serial"] != by_label_2["Serial"]
    assert by_label_1["Role"] == by_label_2["Role"]
    assert by_label_1["Chain"] == by_label_2["Chain"]


def test_review_fields_subject_key_id_uses_the_same_convention_as_signature_exports():
    from seedsigner.models.sevenf.genesis_config import root_id
    req = parse_cert_request_json(json.dumps(_sample_request_dict()).encode("utf-8"))
    by_label = {f.label: f.value for f in review_fields(req)}
    assert by_label["Subject key id"] == root_id(ROOT_VK.hex())
