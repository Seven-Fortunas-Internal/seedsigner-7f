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
    # Testnet for the real-value test plan (docs/multi-chain/evm-test-plan.md) --
    # same address, same plugin, only the chain-id/network-id selection differs, so
    # switching from testnet to Optimism mainnet needs no code change, just picking
    # "optimism" instead of this entry.
    EvmNetwork("optimism-sepolia", "Optimism Sepolia (testnet)", 11155420, "ETH"),
]

NETWORKS_BY_ID = {n.network_id: n for n in NETWORKS}
NETWORKS_BY_CHAIN_ID = {n.chain_id: n for n in NETWORKS}


@dataclass(frozen=True)
class KnownToken:
    symbol: str
    decimals: int


# A token's symbol/decimals are NOT recoverable from calldata alone -- an airgapped
# device has no live way to look them up, so anything not in this table is shown as a
# raw amount + contract address for the operator to verify externally, never guessed.
# This is a bundled, versioned lookup, the same trust model already decided for
# ERC-7730 descriptors (docs/multi-chain/README.md: "staged and versioned with
# releases, not runtime-trusted") -- adding a token here means a new signed release,
# not a runtime download. Addresses are Circle's official USDC deployments
# (https://developers.circle.com/stablecoins/usdc-contract-addresses), verified
# against this module's own EIP-55 checksum before being added.
KNOWN_TOKENS: dict[tuple[int, str], KnownToken] = {
    (10, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"): KnownToken("USDC", 6),           # Optimism
    (11155420, "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"): KnownToken("USDC", 6),      # Optimism Sepolia
}
