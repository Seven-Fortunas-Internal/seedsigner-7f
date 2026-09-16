class BadScanView:
    def _handle_complete_scan(self):
        eth_sign_request = self.decoder.get_eth_sign_request()
        plugin = ChainRegistry.get("evm")
        # ruleid: evm-payload-type-self-validation
        parsed = plugin.parse_sign_request(eth_sign_request.sign_data)
        # ruleid: evm-payload-type-self-validation
        self.controller.multichain_data = dict(
            derivation_path=eth_sign_request.derivation_path,
            payload=eth_sign_request.sign_data,
            fields=parsed.review_fields,
        )


class GoodScanView:
    def _handle_complete_scan(self):
        eth_sign_request = self.decoder.get_eth_sign_request()
        plugin = ChainRegistry.get("evm")
        if not plugin.is_real_transaction_payload(eth_sign_request.sign_data):
            return Destination(EvmUnsupportedSignRequestView)
        # ok: evm-payload-type-self-validation
        parsed = plugin.parse_sign_request(eth_sign_request.sign_data)
        # ok: evm-payload-type-self-validation
        self.controller.multichain_data = dict(
            derivation_path=eth_sign_request.derivation_path,
            payload=eth_sign_request.sign_data,
            fields=parsed.review_fields,
        )


def stash_payload_without_check(req):
    # ruleid: evm-payload-type-self-validation
    self.controller.multichain_data = dict(
        payload=req.sign_data,
    )


def stash_payload_with_check(plugin, req):
    plugin.is_real_transaction_payload(req.sign_data)
    # ok: evm-payload-type-self-validation
    self.controller.multichain_data = dict(
        payload=req.sign_data,
    )


def validated_different_object_is_still_unsafe(plugin, req, other_req):
    plugin.is_real_transaction_payload(other_req.sign_data)
    # ruleid: evm-payload-type-self-validation
    return plugin.parse_sign_request(req.sign_data)


def unrelated_dict_key_is_not_a_sink(req):
    # A "payload" kwarg not sourced from .sign_data shouldn't trip the rule.
    # ok: evm-payload-type-self-validation
    return dict(payload=req.raw_bytes)
