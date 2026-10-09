# A whole 7fchain certificate chain, made by 7fchain's own tools

Every file here was written by `sf-wallet-gov` or `sf-registrar` (7fchain `460f30a`), under the name
it chose, on testnet, so the page's checks are tested against real output:

| File | Made by |
|---|---|
| `root-591c….pem` | `sign-root-cert` (phrase: `abandon` ×23 `art`) |
| `deputy-312f…-csr.pem` | `create-csr --role deputy` (phrase: `letter advice cage … bless`) |
| `deputy-591c….pem` | `sign-deputy-cert` (the Root above certifies the Deputy) |
| `centcom-4408…-csr.pem` | `create-csr --role centcom` (phrase: `legal winner thank … title`) |
| `centcom-312f….pem` | `sign-centcom-cert` (the Deputy certifies CentCom) |
| `registrar-csr.pem` | `sf-registrar keygen` then `csr --name registrar` |
| `x509-miner-issuing-ca.pem` | `sign-issuer-cert --purpose miner --partner-prefix-decimal 1 --seq-lo-decimal 0 --seq-hi-decimal 9` |
| `x509-non-mining-node-issuing-ca.pem` | `sign-issuer-cert --purpose non-mining-node` |

The three phrases are public BIP-39 test vectors and the phrase-file password was `fixture-only`.
Nothing here is a real key.
