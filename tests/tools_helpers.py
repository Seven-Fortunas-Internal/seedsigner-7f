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
