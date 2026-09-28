"""
    7fchain root-key ceremony UI: the no-blind-signing review flow for a
    received genesis-config canonical-bytes payload, and the gated sign
    call. See docs/7f-integration/root-key-ceremony-plan.md.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py, evm_views.py <-> evm_screens.py); see
    gui/screens/sevenf_screens.py for the paired Screen classes.

    Deliberately narrow, matching 7f-signing-support-root-ceremony-review-screen's
    own scope (_delivery/backlog.yaml): parse -> page through every signed
    field -> confirm identity -> sign -> success. No scan-entry-point wiring
    (that's the not-yet-built guided wizard,
    7f-signing-support-root-ceremony-ui-wizard) and no QR/file export of the
    signed result (7f-signing-support-root-ceremony-export-flow, still
    blocked on the BBQr encoding story) -- this flow's entry point is
    SevenFGenesisReviewStartView, constructed directly with the already-
    received canonical_bytes for now.
"""
from gettext import gettext as _

from seedsigner.chains.base import ReviewField
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import genesis_config, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View


class SevenFGenesisReviewStartView(View):
    """ Entry point: parses the received canonical bytes (never trusts a
        separately-supplied "friendly" description of what they contain --
        same self-validation principle as chains/base.py's ChainPlugin
        contract) and stashes the resulting review fields for paging. """
    def __init__(self, seed: Seed, chain_kind: ChainKind, canonical_bytes: bytes):
        super().__init__()
        self.seed = seed

        fields = genesis_config.parse_canonical_bytes(canonical_bytes)
        self.controller.sevenf_ceremony_data = dict(
            seed=seed,
            chain_kind=chain_kind,
            canonical_bytes=canonical_bytes,
            fields=genesis_config.review_fields(fields),
        )


    def run(self):
        return Destination(SevenFGenesisReviewFieldView, view_args=dict(page_num=0), skip_current_view=True)



class SevenFGenesisReviewFieldView(View):
    """ Pages through the genesis-config's review fields one concern per
        screen -- the concrete no-blind-signing mechanism. See
        gui/screens/sevenf_screens.py's SevenFReviewFieldScreen. """
    def __init__(self, page_num: int = 0):
        super().__init__()
        self.page_num = page_num
        data = self.controller.sevenf_ceremony_data
        self.fields: list[ReviewField] = data["fields"]

        if self.page_num >= len(self.fields):
            raise Exception("Bug in 7F genesis-config review field paging")


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFReviewFieldScreen
        field = self.fields[self.page_num]
        is_final_page = self.page_num == len(self.fields) - 1

        selected_menu_num = self.run_screen(
            SevenFReviewFieldScreen,
            page_title=_("Review Genesis Config"),
            label_text=field.label,
            value_text=field.value,
            page_num=self.page_num,
            num_pages=len(self.fields),
            is_final_page=is_final_page,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if self.page_num == 0:
                self.controller.sevenf_ceremony_data = None
            return Destination(BackStackView)

        if is_final_page:
            return Destination(SevenFConfirmSignView)
        else:
            return Destination(SevenFGenesisReviewFieldView, view_args=dict(page_num=self.page_num + 1))



class SevenFConfirmSignView(View):
    """ Final review step: confirms which chain and which Root CA address
        the signature will be attributed to, then performs the actual
        signing. This is the ONLY caller permitted to pass confirmed=True
        into root_ceremony.sign_with_root_ca() -- see that function's own
        docstring for why this is an enforced precondition, not a UI step
        that merely happens to run first. """
    def __init__(self):
        super().__init__()
        data = self.controller.sevenf_ceremony_data
        self.seed: Seed = data["seed"]
        self.chain_kind: ChainKind = data["chain_kind"]
        self.canonical_bytes: bytes = data["canonical_bytes"]

        keys = root_ceremony.derive_root_ceremony_keys(self.seed.seed_bytes, self.chain_kind)
        self.root_ca_address = keys.root_ca.address


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFConfirmSignScreen
        selected_menu_num = self.run_screen(
            SevenFConfirmSignScreen,
            chain_kind_name=self.chain_kind.name.lower(),
            address=self.root_ca_address,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Operator clicked "Sign" -- the one and only call site allowed to pass
        # confirmed=True (root_ceremony.sign_with_root_ca's own docstring).
        public_key, signature = root_ceremony.sign_with_root_ca(
            self.seed.seed_bytes,
            self.chain_kind,
            self.canonical_bytes,
            confirmed=True,
        )
        self.controller.sevenf_ceremony_data["public_key"] = public_key
        self.controller.sevenf_ceremony_data["signature"] = signature
        return Destination(SevenFGenesisSignedView)



class SevenFGenesisSignedView(View):
    """ Success confirmation. Exporting the signed result (QR/file) is
        7f-signing-support-root-ceremony-export-flow's job, not this
        story's -- this view only confirms the signing operation itself
        completed, matching how SeedWordsBackupTestSuccessView plays the
        same role for the backup-verification flow. """
    def run(self):
        from seedsigner.gui.screens.screen import ButtonOption, LargeIconStatusScreen
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Genesis Config Signed"),
            show_back_button=False,
            status_headline=_("Success!"),
            text=_("The genesis-config has been signed with the Root CA key."),
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, skip_current_view=True)
