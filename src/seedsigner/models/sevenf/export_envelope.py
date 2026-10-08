"""
    Ceremony exports that carry their own file name and exact file contents.

    A BBQr header says only "JSON", "text" or "binary", so on its own a scan
    leaves the person to convert it (DER -> PEM) and name it (root-<ski>.pem,
    <ski>.genesis, ...) by hand. Decision (Jorge, 2026-10-07): the QR provides
    the file name. Each export is a small JSON envelope:

        {"sf7_export": 1, "kind": "root-cert",
         "file": "root-<ski>.pem", "body": "<exact file contents>"}

    `body` is byte-for-byte what sf-wallet-gov writes for the same artifact,
    so the host page saves it verbatim; it cross-checks `file` against
    `body` wherever the name is derivable from the content, and refuses a
    mismatch.
"""
import base64
import json

from seedsigner.models.sevenf.review_format import ski

ENVELOPE_VERSION = 1
_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_PEM_END = "-----END CERTIFICATE-----"


def der_to_pem(der: bytes) -> str:
    """ Standard PEM, as sf-wallet-gov writes it: 64-character base64 lines
        and a trailing newline. """
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n".join([_PEM_BEGIN, *lines, _PEM_END]) + "\n"


def pem_to_der(pem: str) -> bytes:
    """ The DER inside a single CERTIFICATE PEM block. """
    text = pem.strip()
    if not (text.startswith(_PEM_BEGIN) and text.endswith(_PEM_END)):
        raise ValueError("not a PEM certificate")
    body = "".join(text[len(_PEM_BEGIN):-len(_PEM_END)].split())
    return base64.b64decode(body, validate=True)


def envelope(kind: str, file: str, body: str) -> bytes:
    return json.dumps(
        {"sf7_export": ENVELOPE_VERSION, "kind": kind, "file": file, "body": body},
        separators=(",", ":"),
    ).encode("utf-8")


def root_cert_export(cert_der: bytes, subject_vk: bytes) -> bytes:
    """ The Root self-certificate as sign-root-cert writes it:
        root-<ski>.pem (runbook Step 2). """
    return envelope("root-cert", f"root-{ski(subject_vk.hex())}.pem", der_to_pem(cert_der))


_SIGNATURE_EXTENSIONS = {"genesis": "genesis", "devfund": "devfund"}


def signature_export(kind: str, signer_vk: bytes, sig: bytes) -> bytes:
    """ A Root signature over a genesis or devfund definition, as
        sf-wallet-gov sign-genesis / sign-devfund write it: <ski>.genesis or
        <ski>.devfund, serde pretty JSON {"signer_vk": "", "sig": hex} plus a
        trailing newline. The key is not embedded (runbook Steps 5-6: the
        coordinator already has it and pairs the signature with <ski>.vk by
        this file name). """
    if kind not in _SIGNATURE_EXTENSIONS:
        raise ValueError(f"unknown signature kind {kind!r}")
    body = json.dumps({"signer_vk": "", "sig": sig.hex()}, indent=2) + "\n"
    return envelope(f"{kind}-sig", f"{ski(signer_vk.hex())}.{_SIGNATURE_EXTENSIONS[kind]}", body)


def deputy_cert_export(cert_der: bytes, issuer_vk: bytes) -> bytes:
    """ A Deputy certificate as sign-deputy-cert writes it:
        deputy-<issuing Root ski>.pem -- named for the issuer, since six Roots
        certify one Deputy and naming by subject would collide. """
    return envelope("deputy-cert", f"deputy-{ski(issuer_vk.hex())}.pem", der_to_pem(cert_der))


_VK_ROLES = ("root", "devfund")


def vk_export(role: str, vk: bytes) -> bytes:
    """ A verification key as sf-wallet-gov writes a .vk (lowercase hex plus a
        newline), tagged with its role: Root and dev-fund keys are both
        <ski>.vk, and the runbook warns one was already sent as the other. """
    if role not in _VK_ROLES:
        raise ValueError(f"unknown vk role {role!r}")
    return envelope(f"{role}-vk", f"{ski(vk.hex())}.vk", vk.hex() + "\n")
