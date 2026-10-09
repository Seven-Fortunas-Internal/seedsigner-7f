"""
    SevenFPlugin -- the ChainPlugin adapter for 7fchain's federation root-key
    ceremony (docs/7f-integration/root-key-ceremony-plan.md). Pure plumbing:
    every method here wraps an already-built, already-tested function in
    models/sevenf/* -- no new crypto or canonical-bytes logic lives here.

    Named as a plugin candidate before any of this existed
    (docs/multi-chain/archive/boot-chain-selection-plan.md: "a third chain (Tron,
    7Fchain)"), and now built as one for the same reason EVM was: its
    signing pipeline is stateless (explicit args in, explicit results out,
    no ambient Controller reads), the same property that made EVM a clean
    ChainRegistry fit and Bitcoin's own retrofit a real rewrite (see that
    doc's "Research findings" section).

    Only parse_sign_request, review_fields and encode_response work.
    derive_address and sign are refused by design: 7F keys come only from a
    24-word governance phrase, and signing only from the 7F menu flows, which
    check the phrase, apply sf-wallet-gov's refusals, show every field and
    take the key index. A generic entry point taking raw seed bytes would
    bypass all of that (the 2026-10-03 signing-oracle finding).

    `payload` is the coordinator's real artifact, `sf-root-coordinator
    prepare-genesis`'s JSON file, not raw canonical bytes: parse_sign_request
    parses it and reviews the canonical bytes `sf-wallet-gov sign-genesis`
    would sign for the same file.
"""
from seedsigner.chains.base import Address, ParsedRequest, ReviewField, Signature
from seedsigner.models.sevenf import genesis_config
from seedsigner.models.sevenf.path_lexicon import root_path



def _canonical_bytes_from_json(payload: bytes) -> tuple[bytes, genesis_config.GenesisConfigFields]:
    """ Parse the real coordinator JSON artifact, build canonical bytes from
        it, then re-parse those bytes through the Rust FFI's own
        parse_canonical_bytes() before returning -- the same build-then-
        reparse round trip SevenFScanGenesisConfigView/
        SevenFGenesisReviewStartView already do (views/sevenf_views/),
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
        """ Refused. 7F keys are derived only from a 24-word governance phrase
            (root_ceremony.seed_for_7f), which raw seed bytes cannot prove, and
            the 7F keys this device holds are CA keys, which have no address
            (sf-wallet-gov prints none). No view calls this. """
        raise NotImplementedError("7F keys are derived only in the 7F menu flows, from a 24-word phrase")


    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        """ `payload` is the genesis-config JSON file the coordinator's
            `sf-root-coordinator prepare-genesis` produces (received over BBQr) -- see
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
        """ Refused. 7F signing happens only in the 7F menu flows: they check
            the phrase (seed_for_7f), apply sf-wallet-gov's refusals, show every
            field and take the key index. A generic entry point taking raw seed
            bytes would bypass all of that (the 2026-10-03 signing-oracle
            finding). No view calls this. """
        raise NotImplementedError("7F signing happens only in the 7F menu flows")


    def encode_response(self, signature: Signature) -> bytes:
        """ Generic hex encoding, matching EvmPlugin.encode_response()'s own
            triviality -- the real export formats (signature-only JSON, BBQr)
            are built directly by views/sevenf_views/'s export views via
            export_envelope.signature_export(), not routed through this
            generic method. """
        return signature.signature_bytes.hex().encode()
