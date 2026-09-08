#!/usr/bin/env python
"""
    Companion tool -- takes a signature produced by one of SeedSigner's real EVM demo
    sign scenarios (chains/evm/plugin.py's DEMO_SCENARIOS) and broadcasts it to
    Optimism Sepolia.

    NEVER touches a private key -- the whole point of the airgapped device is that
    the key never leaves it. This script only combines a signature the device
    already produced with the exact unsigned-transaction fields the device signed --
    decoded from DEMO_SCENARIOS itself (via the same UnsignedEip1559Transaction class
    the device uses), not re-typed here, so there's one source of truth and no risk
    of the tool's field values silently drifting from what the device actually
    signs. See docs/multi-chain/evm-hardware-walkthrough.md for the full walkthrough.

    Usage:
        python tools/broadcast_evm_demo.py <scenario> <signature_hex>

    <scenario> is one of: transfer, approve_unlimited, usdc_transfer
    <signature_hex> is the 130-hex-char (65 byte) value SeedSigner exports via
    EvmSignedQRView -- either read from its QR code (format "EVM-DEMO-SIG:<hex>",
    strip the prefix) or transcribed from the screen.
"""
import json
import os
import sys
import urllib.error
import urllib.request

import rlp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
from seedsigner.chains.evm.transaction import UnsignedEip1559Transaction

RPC_URLS = {
    11_155_420: "https://sepolia.optimism.io",
}
EXPLORER_TX_URLS = {
    11_155_420: "https://sepolia-optimism.etherscan.io/tx/",
}

# permit isn't a real transaction (still Phase 1 / mocked signing) -- nothing to
# broadcast for it, see plugin.py's module docstring.
BROADCASTABLE_SCENARIOS = ("transfer", "approve_unlimited", "usdc_transfer")


def _uint(n: int) -> bytes:
    """Minimal big-endian encoding, no leading zero bytes -- required by RLP."""
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def parse_signature(signature_hex: str) -> tuple[int, int, int]:
    signature_hex = signature_hex.strip()
    if signature_hex.upper().startswith("EVM-DEMO-SIG:"):
        signature_hex = signature_hex.split(":", 1)[1]
    signature_hex = signature_hex.removeprefix("0x").removeprefix("0X")

    signature = bytes.fromhex(signature_hex)
    if len(signature) != 65:
        raise ValueError(
            f"Expected a 65-byte (130 hex char) signature, got {len(signature)} bytes. "
            "Did you copy the full value shown/scanned from the device?")

    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    y_parity = signature[64]
    if y_parity not in (0, 1):
        raise ValueError(f"y_parity byte must be 0 or 1, got {y_parity}")
    return r, s, y_parity


def build_signed_tx(scenario: str, r: int, s: int, y_parity: int) -> tuple[bytes, int]:
    """Returns (raw_signed_tx_bytes, chain_id)."""
    if scenario not in DEMO_SCENARIOS:
        raise ValueError(f"Unknown scenario {scenario!r}. Known: {list(DEMO_SCENARIOS)}")
    if scenario not in BROADCASTABLE_SCENARIOS:
        raise ValueError(
            f"{scenario!r} isn't a real on-chain transaction yet (still Phase 1 -- "
            "see chains/evm/plugin.py's module docstring). Nothing to broadcast.")

    tx = UnsignedEip1559Transaction(DEMO_SCENARIOS[scenario])
    fields = [
        _uint(tx.chain_id), _uint(tx.nonce), _uint(tx.max_priority_fee_per_gas), _uint(tx.max_fee_per_gas),
        _uint(tx.gas_limit), tx.to, _uint(tx.value), tx.data, [],
        _uint(y_parity), _uint(r), _uint(s),
    ]
    return bytes([0x02]) + rlp.encode(fields), tx.chain_id


def broadcast(raw_tx: bytes, chain_id: int) -> str:
    rpc_url = RPC_URLS.get(chain_id)
    if rpc_url is None:
        raise ValueError(f"No known RPC endpoint for chain id {chain_id}")

    request_body = json.dumps({
        "jsonrpc": "2.0", "method": "eth_sendRawTransaction",
        "params": ["0x" + raw_tx.hex()], "id": 1,
    }).encode()
    request = urllib.request.Request(
        rpc_url, data=request_body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read())
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach {rpc_url}: {e}") from e

    if "error" in result:
        raise RuntimeError(f"RPC rejected the transaction: {result['error']}")
    return result["result"]


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    scenario, signature_hex = sys.argv[1], sys.argv[2]
    r, s, y_parity = parse_signature(signature_hex)
    raw_tx, chain_id = build_signed_tx(scenario, r, s, y_parity)
    print("Raw signed tx:", "0x" + raw_tx.hex())

    tx_hash = broadcast(raw_tx, chain_id)
    print("Broadcast OK. Tx hash:", tx_hash)
    explorer_url = EXPLORER_TX_URLS.get(chain_id)
    if explorer_url:
        print("Check status:", explorer_url + tx_hash)


if __name__ == "__main__":
    main()
