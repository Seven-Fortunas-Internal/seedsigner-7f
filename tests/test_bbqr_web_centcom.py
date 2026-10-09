"""
    The 7F Signer page between two computers: the CentCom and registrar files
    an airgap laptop running sf-wallet-gov sends and receives (Buck's laptop
    route, until the SeedSigner signs for CentCom). The sending page wraps the
    file in the same export envelope the device uses; the receiving page checks
    the name against the content before it saves. Fixtures are real 7fchain
    output (tests/fixtures/sf_wallet_gov_chain/README.md). Requires Node.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

TOOL_DIR = Path("tools/bbqr_web_scanner")
CHAIN = Path(__file__).parent / "fixtures" / "sf_wallet_gov_chain"
ROOT_SKI = "591c511984a2d73c6bee1f4dc149d48f7f97fc55"
DEPUTY_SKI = "312f08b216e9300e2357c0e98e2fe40ba0c27056"
CENTCOM_SKI = "4408bb0bd6782e5cfece12d67867b8ad919197fa"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="requires node")

# file -> (kind, subject ski, issuer ski)
CHAIN_FILES = {
    f"root-{ROOT_SKI}.pem": ("root-cert", ROOT_SKI, None),
    f"deputy-{ROOT_SKI}.pem": ("deputy-cert", DEPUTY_SKI, ROOT_SKI),
    f"centcom-{DEPUTY_SKI}.pem": ("centcom-cert", CENTCOM_SKI, DEPUTY_SKI),
    "x509-miner-issuing-ca.pem": ("issuing-ca-cert", None, CENTCOM_SKI),
    "x509-non-mining-node-issuing-ca.pem": ("issuing-ca-cert", None, CENTCOM_SKI),
    f"deputy-{DEPUTY_SKI}-csr.pem": ("csr", DEPUTY_SKI, None),
    f"centcom-{CENTCOM_SKI}-csr.pem": ("csr", CENTCOM_SKI, None),
    "registrar-csr.pem": ("csr", None, None),
}


def _encode(path: Path, *flags: str) -> dict:
    result = subprocess.run(
        ["node", "encode_cli.js", str(path.resolve()), *flags],
        cwd=TOOL_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _decode(parts: list[str], tmp_path) -> bytes:
    seg = tmp_path / "segments.json"
    seg.write_text(json.dumps(parts[::-1]))
    result = subprocess.run(["node", "decode_cli.js", str(seg)], cwd=TOOL_DIR, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return bytes.fromhex(result.stdout)


def _inspect(envelope_text: str) -> dict:
    js = f"require('./bbqr-decode.js').inspectExport({json.dumps(envelope_text)}).then(r => process.stdout.write(JSON.stringify(r)));"
    result = subprocess.run(["node", "-e", js], cwd=TOOL_DIR, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _envelope(name: str) -> dict:
    return json.loads(bytes.fromhex(_encode(CHAIN / name, "--to", "computer")["payloadHex"]))


@pytest.mark.parametrize("name", sorted(CHAIN_FILES))
def test_every_chain_file_crosses_to_a_computer_byte_for_byte_under_its_7fchain_name(name, tmp_path):
    kind, _, _ = CHAIN_FILES[name]
    out = _encode(CHAIN / name, "--to", "computer")
    assert out["kind"] == kind and out["fileType"] == "J"
    payload = _decode(out["parts"], tmp_path)
    assert payload.hex() == out["payloadHex"]
    env = json.loads(payload)
    assert env == {"sf7_export": 1, "kind": kind, "file": name, "body": (CHAIN / name).read_text()}

    r = _inspect(payload.decode())
    assert r["error"] is None, r["error"]
    assert r["kind"] == kind and r["file"] == name
    assert r["body"] == (CHAIN / name).read_text()      # saved exactly as 7fchain wrote it


@pytest.mark.parametrize("name", sorted(CHAIN_FILES))
def test_the_receiver_shows_the_ids_to_check(name):
    kind, ski, issuer = CHAIN_FILES[name]
    r = _inspect(json.dumps(_envelope(name)))
    if ski:
        assert r["ski"] == ski
    if issuer:
        assert r["issuer_ski"] == issuer
    if kind.endswith("-cert"):
        assert r["network"] == "testnet"


def test_an_issuing_ca_names_its_purpose():
    assert _inspect(json.dumps(_envelope("x509-miner-issuing-ca.pem")))["purpose"] == "miner"
    assert _inspect(json.dumps(_envelope("x509-non-mining-node-issuing-ca.pem")))["purpose"] == "non-mining-node"


def test_a_certificate_goes_under_its_7fchain_name_whatever_it_was_called_here(tmp_path):
    f = tmp_path / "from-buck.pem"
    f.write_bytes((CHAIN / f"centcom-{DEPUTY_SKI}.pem").read_bytes())
    out = _encode(f, "--to", "computer")
    assert json.loads(bytes.fromhex(out["payloadHex"]))["file"] == f"centcom-{DEPUTY_SKI}.pem"
    assert any("from-buck.pem" in v for _, v in out["fields"])     # the rename is shown, not silent


def test_a_request_goes_under_the_name_create_csr_gives_it(tmp_path):
    f = tmp_path / "request.pem"
    f.write_bytes((CHAIN / f"centcom-{CENTCOM_SKI}-csr.pem").read_bytes())
    out = _encode(f, "--to", "computer")
    assert json.loads(bytes.fromhex(out["payloadHex"]))["file"] == f"centcom-{CENTCOM_SKI}-csr.pem"
    assert any("request.pem" in v for _, v in out["fields"])


def test_a_request_named_for_another_key_is_not_sent(tmp_path):
    f = tmp_path / f"centcom-{DEPUTY_SKI}-csr.pem"
    f.write_bytes((CHAIN / f"centcom-{CENTCOM_SKI}-csr.pem").read_bytes())
    assert "does not match" in _encode(f, "--to", "computer")["error"]


def test_a_config_is_for_the_seedsigner_only(tmp_path):
    from tools_helpers import REAL_GENESIS_JSON
    f = tmp_path / "genesis-unsigned.json"
    f.write_bytes(REAL_GENESIS_JSON)
    assert "SeedSigner" in _encode(f, "--to", "computer")["error"]


@pytest.mark.parametrize("name", [f"centcom-{DEPUTY_SKI}.pem", "x509-miner-issuing-ca.pem", f"deputy-{ROOT_SKI}.pem"])
def test_the_seedsigner_target_still_takes_only_a_root_certificate(name):
    assert "error" in _encode(CHAIN / name)


def test_the_seedsigner_target_is_unchanged_for_a_root_certificate_and_a_request():
    root = _encode(CHAIN / f"root-{ROOT_SKI}.pem")
    assert root["kind"] == "root-cert" and root["fileType"] == "B"
    csr = _encode(CHAIN / f"deputy-{DEPUTY_SKI}-csr.pem")
    assert csr["kind"] == "deputy-csr" and csr["fileType"] == "B"


@pytest.mark.parametrize("change, needle", [
    (lambda e: {**e, "kind": "issuing-ca-cert"}, "kind"),                          # a CentCom cert is not an issuing CA
    (lambda e: {**e, "file": f"centcom-{ROOT_SKI}.pem"}, "does not match"),         # named for the wrong issuer
    (lambda e: {**e, "body": e["body"].replace("\n", "\r\n")}, "canonical"),
    (lambda e: {**e, "body": e["body"].replace("CERTIFICATE", "CERTIFICATE REQUEST")}, "kind"),
])
def test_the_receiver_refuses_a_centcom_certificate_that_does_not_match(change, needle):
    r = _inspect(json.dumps(change(_envelope(f"centcom-{DEPUTY_SKI}.pem"))))
    assert r["error"] and needle in r["error"], r["error"]


@pytest.mark.parametrize("change, needle", [
    (lambda e: {**e, "file": "x509-l2-sequencer-issuing-ca.pem"}, "does not match"),  # wrong purpose in the name
    (lambda e: {**e, "kind": "centcom-cert"}, "kind"),
])
def test_the_receiver_refuses_an_issuing_ca_that_does_not_match(change, needle):
    r = _inspect(json.dumps(change(_envelope("x509-miner-issuing-ca.pem"))))
    assert r["error"] and needle in r["error"], r["error"]


@pytest.mark.parametrize("change, needle", [
    (lambda e: {**e, "file": f"centcom-{DEPUTY_SKI}-csr.pem"}, "does not match"),
    (lambda e: {**e, "file": "registrar-csr.pem"}, "does not match"),            # a CentCom request passed off as a registrar's
    (lambda e: {**e, "file": f"deputy-{CENTCOM_SKI}-csr.pem"}, "does not match"),  # the right key, the wrong role
    (lambda e: {**e, "file": f"a{CENTCOM_SKI}-csr.pem"}, "does not match"),
    (lambda e: {**e, "file": "centcom.pem"}, "does not match"),
    (lambda e: {**e, "kind": "centcom-cert"}, "kind"),
])
def test_the_receiver_refuses_a_request_that_does_not_match(change, needle):
    r = _inspect(json.dumps(change(_envelope(f"centcom-{CENTCOM_SKI}-csr.pem"))))
    assert r["error"] and needle in r["error"], r["error"]


def test_a_registrar_request_is_only_ever_registrar_csr_pem():
    r = _inspect(json.dumps({**_envelope("registrar-csr.pem"), "file": f"centcom-{CENTCOM_SKI}-csr.pem"}))
    assert r["error"] and "does not match" in r["error"]


def _node_json(js: str):
    result = subprocess.run(["node", "-e", js], cwd=TOOL_DIR, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _with_subject_text(der: bytes, old: bytes, new: bytes) -> bytes:
    """ Same-length substitution in the subject (the issuer's name comes first,
    so the subject's is the last occurrence); no DER lengths change. """
    assert len(old) == len(new) and der.count(old) == 2
    i = der.rindex(old)
    return der[:i] + new + der[i + len(old):]


@pytest.mark.parametrize("new", [b"test\nnt", b"tes\x00net", b"tes\x1bnet", b"\xe2\x80\xaetnet"])
def test_a_subject_field_that_is_not_plain_text_is_not_shown(new):
    import base64
    from seedsigner.models.sevenf.export_envelope import pem_to_der
    der = pem_to_der((CHAIN / f"centcom-{DEPUTY_SKI}.pem").read_text())
    bad = _with_subject_text(der, b"testnet", new)
    r = _node_json(f"require('./bbqr-decode.js').identifyCertificate(Uint8Array.from(Buffer.from('{base64.b64encode(bad).decode()}', 'base64'))).then(r => process.stdout.write(JSON.stringify(r)));")
    assert r.get("network") is None


def test_malformed_der_never_throws(tmp_path):
    import base64
    import random
    from seedsigner.models.sevenf.export_envelope import pem_to_der
    rng = random.Random(7)
    samples = []
    for name in CHAIN_FILES:
        text = (CHAIN / name).read_text()
        der = bytearray(base64.b64decode("".join(text.strip().splitlines()[1:-1])))
        for _ in range(40):
            d = bytearray(der)
            for _ in range(rng.randint(1, 4)):
                d[rng.randrange(len(d))] = rng.randrange(256)
            if rng.random() < 0.3:
                d = d[: rng.randrange(len(d))]
            samples.append(base64.b64encode(bytes(d)).decode())
    samples_file = tmp_path / "samples.json"
    samples_file.write_text(json.dumps(samples))
    js = f"""
const D = require('./bbqr-decode.js');
(async () => {{
  for (const b of JSON.parse(require('fs').readFileSync({json.dumps(str(samples_file))}, 'utf8'))) {{
    const der = Uint8Array.from(Buffer.from(b, 'base64'));
    await D.identifyCertificate(der); await D.identifyRequest(der);
  }}
  process.stdout.write('"ok"');
}})().catch(e => {{ process.stdout.write(JSON.stringify(String(e))); }});
"""
    assert _node_json(js) == "ok"


def _html() -> str:
    return (TOOL_DIR / "index.html").read_text()


def test_the_send_tab_offers_both_receivers():
    html = _html()
    assert 'name="sendTarget"' in html and 'value="device"' in html and 'value="computer"' in html
    assert "sendTarget" in (TOOL_DIR / "app-send.js").read_text()


def test_start_explains_the_computer_to_computer_route():
    start = _html().split('<section id="start"', 1)[1].split("</section>", 1)[0]
    assert "CentCom" in start and "registrar" in start
    assert "sign-centcom-cert" in start and "sign-issuer-cert" in start


def test_the_send_tab_labels_follow_the_chosen_receiver():
    # Found in a browser check: the labels were drawn from the result before
    # the receiver was attached to it, so they always read "On the device".
    src = (TOOL_DIR / "app-send.js").read_text()
    assert "prepared = { ...result, target };" in src and "showPrepared(prepared);" in src


def test_a_registrar_request_offered_to_the_seedsigner_shows_its_requested_name():
    out = _encode(CHAIN / "registrar-csr.pem")
    assert dict(out["fields"])["Requested name (typed by the requester)"] == "registrar"


@pytest.mark.parametrize("name, needle", [
    (f"centcom-{DEPUTY_SKI}.pem", "coordinator"),
    ("x509-miner-issuing-ca.pem", "sf-registrar install"),
])
def test_a_received_certificate_says_what_happens_next_not_where_its_signer_filed_it(name, needle):
    r = _inspect(json.dumps(_envelope(name)))
    assert needle in r["next"] and "folder" not in r


def test_a_received_request_belongs_in_its_signers_inbox():
    assert _inspect(json.dumps(_envelope("registrar-csr.pem")))["folder"].endswith("governance/centcom/inbox")
    assert _inspect(json.dumps(_envelope(f"centcom-{CENTCOM_SKI}-csr.pem")))["folder"].endswith("governance/deputy/inbox")
    assert _inspect(json.dumps(_envelope(f"deputy-{DEPUTY_SKI}-csr.pem")))["folder"].endswith("governance/root/inbox")
