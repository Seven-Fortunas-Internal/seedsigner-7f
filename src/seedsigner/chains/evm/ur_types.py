"""
    ERC-4527 (eth-sign-request / eth-signature) UR types -- the QR protocol
    MetaMask/Rabby/etc. already speak for QR-based hardware wallets (Keystone,
    AirGap, and others), per docs/multi-chain/evm-first-class-plan.md's decision to
    be Keystone-protocol-compatible rather than invent a new one.

    Built on `urtypes` (already a dependency of this codebase, used for Bitcoin's
    PSBT/xpub/account UR types -- see models/decode_qr.py, models/encode_qr.py):
    crypto-keypath itself is NOT reimplemented here, `urtypes.crypto.Keypath` already
    covers it chain-agnostically (a BIP-32 derivation path is the same shape for any
    chain). Only eth-sign-request and eth-signature are new -- `urtypes` doesn't
    define Ethereum-specific types, since those live in ERC-4527, not the
    Blockchain Commons registry.

    Field maps and CBOR tag numbers below are cross-verified against literal test
    vectors from the reference implementation ERC-4527 itself names as authoritative
    (KeystoneHQ/keystone-sdk-base's `ur-registry-eth` package) -- see
    tests/test_evm_ur_types.py, which decodes those exact UR strings and checks every
    field, not just internal round-trip self-consistency. Confirmed against those
    vectors, byte for byte:
      - data-type (key 3) is a bare, untagged integer -- not CBOR-tag-wrapped, despite
        the EIP's CDDL notation reading that way at a glance.
      - derivation-path (key 5) IS tag-wrapped, with crypto-keypath's real registered
        tag, 304 (urtypes.crypto.Keypath.registry_type().tag).
      - request-id (key 1, both types) is tag-wrapped with CBOR tag 37 (UUID), as a
        raw 16-byte string -- no dedicated urtypes type for a bare UUID, handled
        inline here.

    build_account_hdkey_cbor() below (the plan's "Export Connect QR", see
    views/evm_views.py's EvmConnectQRView) is encode-only and reuses
    `urtypes.crypto.HDKey` as-is -- no new registry class needed, unlike
    eth-sign-request/eth-signature above, since crypto-hdkey (tag 303) is already a
    generic Blockchain Commons type this codebase's own Bitcoin xpub export already
    uses (models/encode_qr.py's UrXpubQrEncoder). The one thing worth getting right
    is *which* fields to populate: cross-verified against a real Keystone-produced
    ETH account-hdkey example (KeystoneHQ/Keystone-developer-hub's
    research/ethereum-qr-data-protocol.md), decoded byte-for-byte in
    tests/test_evm_ur_types.py, that real example sets only key/chain_code/origin --
    no use_info (SLIP-44 coin type), no parent_fingerprint, no depth. Matched here
    rather than following UrXpubQrEncoder's fuller Bitcoin shape (which does set
    parent_fingerprint) -- matching real interop matters more than matching this
    codebase's own other UR usage, the same call already made for
    eth-sign-request/eth-signature's omitted `depth` above.
"""
from embit.bip32 import HDKey as Bip32HDKey
from urtypes import RegistryItem, RegistryType
from urtypes.cbor import DataItem, Tagging
from urtypes.crypto import HDKey as UrHDKey, Keypath, PathComponent


ETH_SIGN_REQUEST = RegistryType("eth-sign-request", None)
ETH_SIGNATURE = RegistryType("eth-signature", None)

# sign-data-type enum (eth-sign-request key 3). Only DATA_TYPE_TYPED_TRANSACTION is
# actually supported end to end today -- see EvmScanSignRequestView in
# views/evm_views.py, which refuses everything else outright (self-validation:
# refuse rather than guess, the same rule this codebase applies everywhere else).
DATA_TYPE_TRANSACTION = 1        # legacy (pre-EIP-1559) RLP transaction -- unsupported
DATA_TYPE_TYPED_DATA = 2         # EIP-712 -- unsupported (permit stays mocked, see plugin.py)
DATA_TYPE_RAW_BYTES = 3          # EIP-191 message signing -- unsupported
DATA_TYPE_TYPED_TRANSACTION = 4  # EIP-2718 typed transaction (what real EIP-1559 tx use)

_UUID_TAG = 37


def _path_to_keypath(derivation_path: str, source_fingerprint: bytes = None) -> Keypath:
    """ "m/44'/60'/0'/0/1" -> Keypath. Similar conversion to UrXpubQrEncoder's own
        helper in models/encode_qr.py for Bitcoin xpub export, mirrored rather than
        imported (that one is tied up with BaseXpubQrEncoder's own state), with one
        deliberate difference: `depth` is left unset here. Bitcoin's own xpub export
        always sets it; the real eth-sign-request/eth-signature reference vectors
        this module is cross-verified against (see module docstring) omit it --
        depth is optional per the spec, and matching what real interop actually
        produces matters more here than matching this codebase's other UR usage. """
    parts = derivation_path.split("/")
    if parts and parts[0].lower() == "m":
        parts = parts[1:]
    parts = [p for p in parts if p != ""]

    components = []
    for part in parts:
        if part.endswith("'") or part.endswith("h") or part.endswith("H"):
            components.append(PathComponent(int(part[:-1]), True))
        else:
            components.append(PathComponent(int(part), False))
    return Keypath(components, source_fingerprint, None)


def _keypath_to_path(keypath: Keypath) -> str:
    """ Keypath -> "m/44'/60'/0'/0/1". Inverse of _path_to_keypath. """
    return "m/" + keypath.path()


class EthSignRequest(RegistryItem):
    """ Incoming request: what MetaMask/Rabby/etc. send, asking the device to sign
        `sign_data`. `derivation_path` is a plain "m/44'/..." string (this codebase's
        own convention, e.g. chains/evm/plugin.py's DERIVATION_PATH_TEMPLATE) --
        converted to/from the CBOR crypto-keypath structure at the edges, so nothing
        upstream of this module needs to know about Keypath/PathComponent at all. """
    def __init__(self, sign_data: bytes, data_type: int, chain_id: int, derivation_path: str,
                 request_id: bytes = None, address: bytes = None, origin: str = None):
        super().__init__()
        self.sign_data = sign_data
        self.data_type = data_type
        self.chain_id = chain_id
        self.derivation_path = derivation_path
        self.request_id = request_id
        self.address = address
        self.origin = origin


    @classmethod
    def registry_type(cls):
        return ETH_SIGN_REQUEST


    def to_data_item(self):
        fields = {}
        if self.request_id is not None:
            fields[1] = Tagging(_UUID_TAG, self.request_id)
        fields[2] = self.sign_data
        fields[3] = self.data_type
        fields[4] = self.chain_id
        fields[5] = Tagging(Keypath.registry_type().tag, _path_to_keypath(self.derivation_path).to_data_item())
        if self.address is not None:
            fields[6] = self.address
        if self.origin is not None:
            fields[7] = self.origin
        return fields


    @classmethod
    def from_data_item(cls, item):
        fields = cls.mapping(item)

        request_id = None
        if 1 in fields:
            v = fields[1]
            request_id = v.map if isinstance(v, DataItem) else v

        sign_data = fields[2]
        data_type = fields[3]
        chain_id = fields[4]
        derivation_path = _keypath_to_path(Keypath.from_data_item(fields[5]))
        address = fields.get(6)
        origin = fields.get(7)

        return cls(sign_data, data_type, chain_id, derivation_path, request_id, address, origin)


class EthSignature(RegistryItem):
    """ Outgoing response: the device's signature, matched back to the request it
        answers via `request_id` (must be byte-identical to the request's, not
        regenerated -- that's how the requester correlates response to request). """
    def __init__(self, request_id: bytes, signature: bytes, origin: str = None):
        super().__init__()
        self.request_id = request_id
        self.signature = signature
        self.origin = origin


    @classmethod
    def registry_type(cls):
        return ETH_SIGNATURE


    def to_data_item(self):
        fields = {
            1: Tagging(_UUID_TAG, self.request_id),
            2: self.signature,
        }
        if self.origin is not None:
            fields[3] = self.origin
        return fields


    @classmethod
    def from_data_item(cls, item):
        fields = cls.mapping(item)
        v = fields[1]
        request_id = v.map if isinstance(v, DataItem) else v
        signature = fields[2]
        origin = fields.get(3)
        return cls(request_id, signature, origin)


# Account-level prefix of plugin.py's DERIVATION_PATH_TEMPLATE ("m/44'/60'/{account}'/0/{index}")
# -- duplicated as a bare constant rather than imported, matching this module's existing
# mirror-don't-import stance on path handling (see _path_to_keypath above).
_ACCOUNT_PATH_TEMPLATE = "m/44'/60'/{account}'"


def build_account_hdkey_cbor(seed_bytes: bytes, account: int = 0) -> bytes:
    """ Builds the CBOR body for a crypto-hdkey UR exporting the account-level
        (m/44'/60'/{account}') extended *public* key -- the "Connect" QR a real
        requester (MetaMask/Rabby/etc.) scans to import a Keystone-compatible
        watch-only account, after which it derives whichever change/index address
        it needs on its own, without a further QR round-trip. Deliberately
        different from every other derivation in this module/plugin.py, which
        always goes to a full m/44'/60'/{account}'/0/{index} leaf and returns a
        private key or address -- this is the one place an *account-level public*
        key leaves the device, by design (a watch-only export, not a signing one).

        seed_bytes already has any BIP-39 passphrase mixed in (Seed.seed_bytes),
        same as chains/evm/crypto.py's derive_private_key -- honored here for the
        same reason (see crypto.py's module docstring). """
    root = Bip32HDKey.from_seed(seed_bytes)
    account_node = root.derive(_ACCOUNT_PATH_TEMPLATE.format(account=account))
    account_pub = account_node.to_public()

    origin = Keypath(
        [PathComponent(44, True), PathComponent(60, True), PathComponent(account, True)],
        root.my_fingerprint,
        None,  # depth omitted -- see module docstring: matches the real reference example
    )
    ur_hdkey = UrHDKey({
        "key": account_pub.sec(),
        "chain_code": account_pub.chain_code,
        "origin": origin,
    })
    return ur_hdkey.to_cbor()
