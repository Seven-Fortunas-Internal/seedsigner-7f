class BadScanView:
    def _handle_complete_scan(self):
        eth_sign_request = self.decoder.get_eth_sign_request()
        # ruleid: evm-derivation-path-self-validation
        self.controller.multichain_data = dict(
            seed=self.seed,
            chain_id="evm",
            derivation_path=eth_sign_request.derivation_path,
            payload=eth_sign_request.sign_data,
        )


class GoodScanView:
    def _handle_complete_scan(self):
        eth_sign_request = self.decoder.get_eth_sign_request()
        plugin = ChainRegistry.get("evm")
        plugin.validate_derivation_path(eth_sign_request.derivation_path)
        # ok: evm-derivation-path-self-validation
        self.controller.multichain_data = dict(
            seed=self.seed,
            chain_id="evm",
            derivation_path=eth_sign_request.derivation_path,
            payload=eth_sign_request.sign_data,
        )


def sign_without_check(plugin, seed_bytes, req):
    # ruleid: evm-derivation-path-self-validation
    return plugin.sign(seed_bytes, req.derivation_path, req.sign_data)


def sign_with_check(plugin, seed_bytes, req):
    plugin.validate_derivation_path(req.derivation_path)
    # ok: evm-derivation-path-self-validation
    return plugin.sign(seed_bytes, req.derivation_path, req.sign_data)


def operator_chosen_path_is_fine(plugin, seed_bytes, address_index):
    # Not sourced from a decoded object's .derivation_path attribute at all --
    # this is the demo-menu path, built from an operator-picked index.
    path = DERIVATION_PATH_TEMPLATE.format(account=0, index=address_index)
    # ok: evm-derivation-path-self-validation
    return plugin.sign(seed_bytes, path, b"")


def just_displaying_is_not_a_sink(req):
    # Reading .derivation_path for display only (no signing/hand-off sink in
    # this function) shouldn't trip the rule.
    # ok: evm-derivation-path-self-validation
    return ReviewField(label="Derivation Path", value=req.derivation_path)


def validated_but_different_object_is_still_unsafe(plugin, seed_bytes, req, other_req):
    # Validates other_req's path but signs with req's -- must still fire since
    # it's not the same value that was checked.
    plugin.validate_derivation_path(other_req.derivation_path)
    # ruleid: evm-derivation-path-self-validation
    return plugin.sign(seed_bytes, req.derivation_path, req.sign_data)
