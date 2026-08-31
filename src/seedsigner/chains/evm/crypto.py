"""
    Real EVM cryptography -- rollout Phase 2. Two primitives, both reused rather than
    reimplemented:

    - BIP-32/secp256k1 HD derivation and raw ECDSA signing go through embit's existing
      secp256k1 C binding (embit.ec / embit.bip32) -- the exact primitive already
      proven on this hardware for Bitcoin. No second elliptic-curve implementation is
      introduced; Ethereum uses the same curve, just a different address encoding and
      a recoverable (vs plain) signature.
    - Keccak-256 (Ethereum's hash, NOT the NIST-standardized SHA3-256 -- different
      padding) comes from pycryptodome, which has prebuilt piwheels ARM wheels for
      this hardware (verified before adding the dependency).

    seed_bytes here is always Seed.seed_bytes -- which already has any BIP-39
    passphrase mixed in via bip39.mnemonic_to_seed(password=passphrase). Unlike the
    (paused) 7F work, EVM does not special-case or refuse a passphrase: standard
    BIP-39 passphrase wallets are an expected, ecosystem-wide feature (MetaMask,
    Ledger, Trezor all support them), so honoring it here is the standard, and
    therefore correct, behavior -- verified below to produce byte-identical results
    to eth_account given the same mnemonic + passphrase (see tests/test_evm_crypto.py).
"""
from Crypto.Hash import keccak
from embit.bip32 import HDKey
from embit.ec import PrivateKey, secp256k1


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def derive_private_key(seed_bytes: bytes, path: str) -> bytes:
    """Standard BIP-32 derivation -- chain-agnostic; only the path's purpose field
    (44'/60') and the address encoding below are Ethereum-specific."""
    root = HDKey.from_seed(seed_bytes)
    child = root.derive(path)
    return child.secret


def private_key_to_checksum_address(private_key: bytes) -> str:
    """secp256k1 pubkey -> Keccak-256 -> last 20 bytes -> EIP-55 checksum casing."""
    public_key = PrivateKey(private_key).get_public_key()
    public_key.compressed = False
    uncompressed = public_key.sec()  # 65 bytes: 0x04 prefix + 32-byte X + 32-byte Y
    address_bytes = keccak256(uncompressed[1:])[-20:]
    return address_bytes_to_checksum(address_bytes)


def address_bytes_to_checksum(address_bytes: bytes) -> str:
    """EIP-55: uppercase each hex digit of the address whose corresponding nibble in
    keccak256(lowercase hex address) is >= 8. A mixed-case typo-detection encoding,
    not a security boundary on its own -- callers still compare full addresses.
    Public: also used to display a 20-byte address recovered from raw transaction/
    calldata bytes (chains/evm/transaction.py, chains/evm/erc20.py), not just one
    derived from a private key."""
    if len(address_bytes) != 20:
        raise ValueError(f"Ethereum address must be 20 bytes, got {len(address_bytes)}")
    hex_address = address_bytes.hex()
    digest_hex = keccak256(hex_address.encode()).hex()
    return "0x" + "".join(
        c.upper() if int(h, 16) >= 8 else c
        for c, h in zip(hex_address, digest_hex)
    )


def sign_hash_recoverable(private_key: bytes, msg_hash: bytes) -> tuple[int, int, int]:
    """Sign a 32-byte hash, returning (r, s, y_parity). y_parity is 0 or 1 (the
    EIP-1559/typed-transaction convention); add 27 for legacy-transaction `v`.
    Caller is responsible for computing msg_hash from the raw payload itself
    (self-validation: never sign a hash that was only claimed, not recomputed)."""
    if len(msg_hash) != 32:
        raise ValueError("msg_hash must be 32 bytes")
    recoverable_sig = secp256k1.ecdsa_sign_recoverable(msg_hash, private_key)
    compact, recovery_id = secp256k1.ecdsa_recoverable_signature_serialize_compact(recoverable_sig)
    r = int.from_bytes(compact[:32], "big")
    s = int.from_bytes(compact[32:], "big")
    return r, s, recovery_id
