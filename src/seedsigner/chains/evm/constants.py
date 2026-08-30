"""
    EVM network table. One shared plugin covers all EVM chains (same signing
    algorithm, address format, and core tx/calldata structure -- see
    docs/multi-chain/README.md "Chain scope, v1"); adding a new EVM chain later means
    adding a row here, not a new module.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class EvmNetwork:
    network_id: str     # short key used in derivation-path/menu plumbing
    display_name: str
    chain_id: int        # EIP-155 chain ID
    native_symbol: str


NETWORKS: list[EvmNetwork] = [
    EvmNetwork("ethereum", "Ethereum", 1, "ETH"),
    EvmNetwork("base", "Base", 8453, "ETH"),
    EvmNetwork("optimism", "Optimism", 10, "ETH"),
]

NETWORKS_BY_ID = {n.network_id: n for n in NETWORKS}
