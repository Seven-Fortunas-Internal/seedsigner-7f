""" Shared real 7fchain artifacts for tool tests. """

# `sf-root-coordinator prepare-genesis` output, 7fchain 416f576 (2026-10-07 end-to-end run).
REAL_GENESIS_JSON = b"""{
  "version": 1,
  "chain_kind": "testnet",
  "timestamp": 1791425505,
  "message": "e2e quorum test 2026-10-07",
  "derivation_scheme": "7fchain.ml-dsa-keygen.v1",
  "consensus": {
    "target_block_time_secs": 420,
    "difficulty_adjustment_interval_blocks": 1500,
    "blocks_per_decay_period": 70000
  },
  "signatures": []
}"""


def parse_issued_cert(der: bytes):
    """ Test-only reader for an issued (Deputy) certificate: subject key, chain
        kind (subject OU) and validity. parse_root_certificate_der is now
        strict -- canonical Root DN, SKI and self-signature -- so it rightly
        refuses a Deputy certificate. """
    from calendar import timegm
    from datetime import datetime
    from types import SimpleNamespace
    from seedsigner.models.sevenf.cert_request import _der_children, _der_tlv
    from seedsigner.models.sevenf.constants import ChainKind

    _, _, s, e = _der_tlv(der, 0)
    tbs = _der_children(der, *_der_children(der, s, e)[0][2:4])
    if tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    _serial, _alg, _issuer, validity, subject, spki = tbs[:6]

    def time_of(t):
        raw = der[t[2]:t[3]].decode()
        fmt = "%y%m%d%H%M%SZ" if t[0] == 0x17 else "%Y%m%d%H%M%SZ"
        return timegm(datetime.strptime(raw, fmt).timetuple())

    not_before, not_after = (time_of(t) for t in _der_children(der, validity[2], validity[3]))
    ou = None
    for rdn in _der_children(der, subject[2], subject[3]):
        for atv in _der_children(der, rdn[2], rdn[3]):
            oid, value = _der_children(der, atv[2], atv[3])
            if der[oid[2]:oid[3]] == bytes.fromhex("55040b"):  # 2.5.4.11 OU
                ou = der[value[2]:value[3]].decode()
    bits = _der_children(der, spki[2], spki[3])[1]
    return SimpleNamespace(
        subject_vk=der[bits[2] + 1:bits[3]],
        chain_kind={k.name.lower(): k for k in ChainKind}[ou],
        not_before=not_before,
        not_after=not_after,
    )
