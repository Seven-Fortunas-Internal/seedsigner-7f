"""
    SevenFPlugin -- the ChainPlugin adapter for 7fchain's federation root-key
    ceremony (docs/7f-integration/root-key-ceremony-plan.md). Pure plumbing:
    every method here wraps an already-built, already-tested function in
    models/sevenf/* -- no new crypto or canonical-bytes logic lives here.

    Named as a plugin candidate before any of this existed
    (docs/multi-chain/boot-chain-selection-plan.md: "a third chain (Tron,
    7Fchain)"), and now built as one for the same reason EVM was: its
    signing pipeline is stateless (explicit args in, explicit results out,
    no ambient Controller reads), the same property that made EVM a clean
    ChainRegistry fit and Bitcoin's own retrofit a real rewrite (see that
    doc's "Research findings" section).

    Two intentional departures from a literal 1:1 EvmPlugin mirror, both
    tied to properties unique to 7F's ceremony (not oversights):
    - `sign()` ignores its own `path` argument and re-derives chain_kind
      from `payload` itself (genesis_config.parse_genesis_config_json())
      rather than trusting a separately-supplied path -- the same
      self-validation fix already applied to SevenFGenesisReviewStartView
      (sevenf_views.py) for the identical reason: a path argument could
      diverge from what's actually inside the bytes being signed.
    - `sign()` always passes confirmed=True into
      root_ceremony.sign_with_root_ca() -- consistent with EvmPlugin.sign()
      itself having no confirmation gate (no-blind-signing lives in the view
      layer for both chains); the *extra* structural gate inside
      sign_with_root_ca() stays as defense-in-depth, unused by any other
      caller.

    RESOLVED 2026-10-03 (7f-signing-support-genesis-wire-envelope-undefined):
    `payload` is the REAL coordinator artifact -- `sf-root prepare-genesis`'s
    JSON file -- not raw canonical bytes. Both methods below parse it with
    genesis_config.parse_genesis_config_json() and, where signing is
    involved, build canonical bytes from the extracted fields before
    signing, so the signature covers the exact bytes `sf-root sign-genesis`
    would sign for the same file.
"""
from seedsigner.chains.base import Address, ParsedRequest, ReviewField, Signature
from seedsigner.models.sevenf import genesis_config, mldsa, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind, Layer, root_path


def _chain_kind_from_path(path: str) -> ChainKind:
    """ 7F derivation paths embed chain_kind literally as one path segment
        (e.g. "root/testnet/0/ml-dsa/v1" -- constants.py's own
        ChainKind.path_segment), so this recovers it without a second,
        separately-supplied argument that could drift from the path
        string's own content. """
    for chain_kind in ChainKind:
        if f"/{chain_kind.path_segment}/" in path:
            return chain_kind
    raise ValueError(f"Could not determine chain_kind from 7F derivation path: {path!r}")


def _canonical_bytes_from_json(payload: bytes) -> tuple[bytes, genesis_config.GenesisConfigFields]:
    """ Parse the real coordinator JSON artifact, build canonical bytes from
        it, then re-parse those bytes through the Rust FFI's own
        parse_canonical_bytes() before returning -- the same build-then-
        reparse round trip SevenFScanGenesisConfigView/
        SevenFGenesisReviewStartView already do (views/sevenf_views.py),
        added here for the same reason (adversarial review, 2026-10-03):
        the FFI-verified fields are what get shown for review and what get
        signed, not a second, independently-interpreted copy of the JSON
        that could in principle drift from them -- the exact class of bug
        this module's own docstring already documents once (the "Derivation
        scheme" line that silently went missing, genesis_config.py's
        test_genesis_config_review_lines_contains_all_fields). """
    json_fields = genesis_config.parse_genesis_config_json(payload)
    canonical_bytes = genesis_config.build_canonical_bytes(
        json_fields.chain_kind, json_fields.timestamp, json_fields.message, json_fields.consensus,
    )
    fields = genesis_config.parse_canonical_bytes(canonical_bytes)
    return canonical_bytes, fields


class SevenFPlugin:
    chain_id = "sevenf"
    display_name = "7F Chain"

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        """ `path` must be one of root_path()'s own output for some
            ChainKind -- not yet exercised by any current UI (the ceremony
            flow itself never browses an address; it only derives the Root
            key at sign time, from the chain_kind embedded in a scanned
            genesis-config). Implemented for real rather than stubbed so a
            future "view Root address" screen has a working,
            already-correct entry point. """
        chain_kind = _chain_kind_from_path(path)
        public_key, address = mldsa.derive_pubkey(
            seed_bytes, path, int(chain_kind), int(Layer.L1),
        )
        return Address(path=path, address=address, network_name=chain_kind.name.lower())


    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        """ `payload` is the genesis-config JSON file the coordinator's
            `sf-root prepare-genesis` produces (received over BBQr) -- see
            genesis_config.py's own docstring for the parser's
            self-validation. """
        canonical, fields = _canonical_bytes_from_json(payload)
        return ParsedRequest(
            operation="Genesis Config",
            network_name=fields.chain_kind.name.lower(),
            derivation_path=root_path(fields.chain_kind),
            review_fields=genesis_config.review_fields(fields, canonical_bytes=canonical),
        )


    def review_fields(self, parsed: ParsedRequest) -> list[ReviewField]:
        return parsed.review_fields


    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        """ `path` is intentionally unused -- see this module's own docstring
            for why chain_kind must come from `payload` itself, never a
            separately-supplied argument. """
        canonical_bytes, fields = _canonical_bytes_from_json(payload)
        public_key, signature_bytes = root_ceremony.sign_with_root_ca(
            seed_bytes, fields.chain_kind, canonical_bytes, confirmed=True,
        )
        return Signature(signature_bytes=signature_bytes, public_key=public_key)


    def encode_response(self, signature: Signature) -> bytes:
        """ Generic hex encoding, matching EvmPlugin.encode_response()'s own
            triviality -- the real export formats (signature-only JSON, BBQr)
            are built directly by sevenf_views.py's export views via
            genesis_config.build_root_sig_json(), not routed through this
            generic method. """
        return signature.signature_bytes.hex().encode()
