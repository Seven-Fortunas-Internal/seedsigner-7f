import logging
import re

from gettext import gettext as _
from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import BackStackView, ErrorView, MainMenuView, NotYetImplementedView, View, Destination
from seedsigner.gui.screens.screen import ButtonOption

logger = logging.getLogger(__name__)



class ScanView(View):
    """
        The catch-all generic scanning View that will accept any of our supported QR
        formats and will route to the most sensible next step.

        Can also be used as a base class for more specific scanning flows with
        dedicated errors when an unexpected QR type is scanned (e.g. Scan PSBT was
        selected but a SeedQR was scanned).
    """
    instructions_text = _mft("Scan a QR code")
    invalid_qr_type_message = _mft("QRCode not recognized or not yet supported.")


    def __init__(self):
        from seedsigner.models.decode_qr import DecodeQR

        super().__init__()
        # Define the decoder here to make it available to child classes' is_valid_qr_type
        # checks and so we can inject data into it in the test suite's `before_run()`.
        self.wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        self.decoder: DecodeQR = DecodeQR(wordlist_language_code=self.wordlist_language_code)


    @property
    def is_valid_qr_type(self):
        return True


    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

        # Start the live preview and background QR reading
        self.run_screen(
            ScanScreen,
            instructions_text=self.instructions_text,
            decoder=self.decoder
        )

        # A long scan might have exceeded the screensaver timeout; ensure screensaver
        # doesn't immediately engage when we leave here.
        self.controller.reset_screensaver_timeout()

        # Handle the results
        if self.decoder.is_complete:
            if not self.is_valid_qr_type:
                # We recognized the QR type but it was not the type expected for the
                # current flow.
                # Report QR types in more human-readable text (e.g. QRType
                # `seed__compactseedqr` as "seed: compactseedqr").
                # TODO: cleanup l10n presentation
                return Destination(ErrorView, view_args=dict(
                    title="Error",
                    status_headline=_("Wrong QR Type"),
                    text=_(self.invalid_qr_type_message) + f""", received "{self.decoder.qr_type.replace("__", ": ").replace("_", " ")}\" format""",
                    button_text="Back",
                    next_destination=Destination(BackStackView, skip_current_view=True),
                ))

            return self._handle_complete_scan()

        elif self.decoder.is_invalid:
            # For now, don't even try to re-do the attempted operation, just reset and
            # start everything over.
            self.controller.resume_main_flow = None
            return Destination(ScanInvalidQRTypeView)

        return Destination(MainMenuView)


    def _handle_complete_scan(self):
        """ What to do with a successfully-decoded, correctly-typed scan. Split out
            from run() as its own overridable method so a chain-scoped scan flow
            that already knows its seed (e.g. EvmScanSignRequestView, reached from
            within a specific seed's own submenu, unlike this catch-all view) can
            supply its own dispatch without duplicating run()'s shared
            scan-screen/is_valid_qr_type/is_invalid scaffolding above. """
        if self.decoder.is_seed:
            seed_mnemonic = self.decoder.get_seed_phrase()

            if not seed_mnemonic:
                # seed is not valid, Exit if not valid with message
                return Destination(NotYetImplementedView)
            else:
                # Found a valid mnemonic seed! All new seeds should be considered
                #   pending (might set a passphrase, SeedXOR, etc) until finalized.
                from seedsigner.models.seed import Seed
                from .seed_views import SeedFinalizeView
                self.controller.storage.set_pending_seed(
                    Seed(mnemonic=seed_mnemonic, wordlist_language_code=self.wordlist_language_code)
                )
                if self.settings.get_value(SettingsConstants.SETTING__PASSPHRASE) == SettingsConstants.OPTION__REQUIRED:
                    from seedsigner.views.seed_views import SeedAddPassphraseView
                    return Destination(SeedAddPassphraseView)
                else:
                    return Destination(SeedFinalizeView)

        elif self.decoder.is_psbt:
            if self.controller.active_chain_id != "bitcoin":
                # Fail-closed, checked before any decode/parse work (get_psbt() below
                # does the real embit PSBT parse) -- PSBTSelectSeedView itself has no
                # active_chain_id guard of its own, unlike is_address/is_sign_message
                # below, so this dispatch-level check is the only thing closing this
                # gap (found by the 2026-09-26 cluster-wide adversarial review).
                return Destination(MainMenuView, clear_history=True)
            from seedsigner.views.psbt_views import PSBTSelectSeedView
            psbt = self.decoder.get_psbt()
            self.controller.psbt = psbt
            self.controller.psbt_parser = None
            return Destination(PSBTSelectSeedView, skip_current_view=True)

        elif self.decoder.is_settings:
            from seedsigner.views.settings_views import SettingsIngestSettingsQRView
            data = self.decoder.get_settings_data()
            return Destination(SettingsIngestSettingsQRView, view_args=dict(data=data))

        elif self.decoder.is_wallet_descriptor:
            if self.controller.active_chain_id != "bitcoin":
                # Same rationale as is_psbt above -- MultisigWalletDescriptorView has
                # no guard of its own either.
                return Destination(MainMenuView, clear_history=True)
            from embit.descriptor import Descriptor
            from seedsigner.views.seed_views import MultisigWalletDescriptorView
            descriptor_str = self.decoder.get_wallet_descriptor()

            try:
                # We need to replace `/0/*` wildcards with `/{0,1}/*` in order to use
                # the Descriptor to verify change, too.
                orig_descriptor_str = descriptor_str
                if len(re.findall (r'\[([0-9,a-f,A-F]+?)(\/[0-9,\/,h\']+?)\].*?(\/0\/\*)', descriptor_str)) > 0:
                    p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h\']+?\].*?)(\/0\/\*)')
                    descriptor_str = p.sub(r'\1/{0,1}/*', descriptor_str)
                elif len(re.findall (r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])', descriptor_str)) > 0:
                    p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])')
                    descriptor_str = p.sub(r'\1/{0,1}/*\2', descriptor_str)
            except Exception as e:
                logger.info(repr(e), exc_info=True)
                descriptor_str = orig_descriptor_str

            descriptor = Descriptor.from_string(descriptor_str)

            if not descriptor.is_basic_multisig:
                # TODO: Handle single-sig descriptors?
                logger.info(f"Received single sig descriptor: {descriptor}")
                return Destination(NotYetImplementedView)

            self.controller.multisig_wallet_descriptor = descriptor
            return Destination(MultisigWalletDescriptorView, skip_current_view=True)

        elif self.decoder.is_address:
            if self.controller.active_chain_id != "bitcoin":
                # AddressVerificationStartView already guards itself (defense-in-depth,
                # added the night before this story) -- this dispatch-level check adds
                # the "before any decode/parse work" property get_address()/
                # get_address_type() below would otherwise skip.
                return Destination(MainMenuView, clear_history=True)
            from seedsigner.views.seed_views import AddressVerificationStartView
            address = self.decoder.get_address()
            (script_type, network) = self.decoder.get_address_type()

            return Destination(
                AddressVerificationStartView,
                skip_current_view=True,
                view_args={
                    "address": address,
                    "script_type": script_type,
                    "network": network,
                }
            )

        elif self.decoder.is_evm_address:
            if self.controller.active_chain_id != "evm":
                # An EVM address scanned while in Bitcoin mode is out of scope, same
                # treatment as any other out-of-scope QR -- EvmVerifyAddressStartView
                # also guards itself, defense-in-depth, same pattern as every other
                # branch in this method.
                return Destination(MainMenuView, clear_history=True)
            from seedsigner.views.evm_views import EvmVerifyAddressStartView
            address = self.decoder.get_evm_address()

            return Destination(EvmVerifyAddressStartView, skip_current_view=True, view_args=dict(address=address))

        elif self.decoder.is_sign_message:
            if self.controller.active_chain_id != "bitcoin":
                # SeedSignMessageStartView already guards itself (defense-in-depth,
                # the HIGH finding fixed the night before this story) -- same
                # before-any-decode-work rationale as is_address above.
                return Destination(MainMenuView, clear_history=True)
            from seedsigner.views.seed_views import SeedSignMessageStartView
            qr_data = self.decoder.get_qr_data()

            return Destination(
                SeedSignMessageStartView,
                view_args=dict(
                    derivation_path=qr_data["derivation_path"],
                    message=qr_data["message"],
                )
            )

        elif self.decoder.is_eth_sign_request:
            if self.controller.active_chain_id != "evm":
                # Checked here, BEFORE get_eth_sign_request()'s real CBOR parse below --
                # a check placed only inside EvmSelectSeedView.__init__ (which still
                # keeps its own guard too, as defense-in-depth) would let the full
                # parse of attacker-controlled bytes run first in the wrong chain mode
                # (multi-chain-boot-chain-selection-scan-gating).
                return Destination(MainMenuView, clear_history=True)
            # No Controller state is touched here beyond the check above: the decoded
            # request is used only to build EvmSelectSeedView's seed-selection hint and
            # then discarded (double-scan design -- see
            # docs/multi-chain/scan-recognizes-eth-sign-request-plan.md). The operator
            # scans the same QR again inside EvmScanSignRequestView for the real,
            # fully-validated review.
            from seedsigner.views.evm_views import EvmSelectSeedView, EvmUnsupportedSignRequestView
            eth_sign_request = self.decoder.get_eth_sign_request()
            if eth_sign_request is None:
                # is_eth_sign_request only checks the UR-type prefix, independent of
                # whether the CBOR body actually decodes into a valid EthSignRequest
                # (get_eth_sign_request() has its own try/except around that and
                # returns None on failure) -- same "refuse rather than guess" handling
                # EvmScanSignRequestView._handle_complete_scan() already uses for the
                # identical failure mode on the second scan (found by execution-stage
                # adversarial review; this dispatch branch had no check at all before).
                return Destination(EvmUnsupportedSignRequestView, view_args=dict(
                    reason=_("Couldn't decode the scanned request.")))
            return Destination(EvmSelectSeedView, view_args=dict(eth_sign_request=eth_sign_request))

        else:
            return Destination(NotYetImplementedView)



class ScanPSBTView(ScanView):
    instructions_text = _mft("Scan Transaction")
    invalid_qr_type_message = _mft("Expected a transaction")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_psbt



class ScanSeedQRView(ScanView):
    instructions_text = _mft("Scan SeedQR")
    invalid_qr_type_message = _mft("Expected a SeedQR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_seed



class ScanWalletDescriptorView(ScanView):
    instructions_text = _mft("Scan descriptor")
    invalid_qr_type_message = _mft("Expected a wallet descriptor QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_wallet_descriptor



class ScanAddressView(ScanView):
    instructions_text = _mft("Scan address QR")
    invalid_qr_type_message = _mft("Expected an address QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_address



class ScanInvalidQRTypeView(View):
    def run(self):
        from seedsigner.gui.screens import WarningScreen

        # TODO: This screen says "Error" but is intentionally using the WarningScreen in
        # order to avoid the perception that something is broken on our end. This should
        # either change to use the red ErrorScreen or the "Error" title should be
        # changed to something softer.
        self.run_screen(
            WarningScreen,
            title=_("Error"),
            status_headline=_("Unknown QR Type"),
            text=_("QRCode is invalid or is a data format not yet supported."),
            button_data=[ButtonOption("Back to Main Menu")],
        )

        return Destination(MainMenuView, clear_history=True)
