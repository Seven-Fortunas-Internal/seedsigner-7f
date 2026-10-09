"""
    Shared infrastructure used across more than one 7F ceremony flow:
    pagination, the "scan didn't parse" refusal screen, the generic
    CertRequest-shaped review pager (Root self-cert, Deputy cross-cert,
    and devfund-config all page through it), and the confirm-sign/signed
    pair shared by Root self-cert and Deputy cross-cert specifically
    (both sign an arbitrary TBS body with the same Root key).

    Split out of the former monolithic sevenf_views.py 2026-10-04
    (7f-review-sevenf-views-py-split, found by the full-project
    adversarial review's Python-code-quality and modularity dimensions):
    that file held four independent ceremony flows plus this shared
    infrastructure in one 1,106-line module, well over this project's own
    800-line soft ceiling. See the package's own __init__.py docstring for
    the full split rationale and the module map.
"""
from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.review import ReviewField
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf.mldsa import MlDsaError
from seedsigner.models.sevenf import config_json, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.path_lexicon import root_path
from seedsigner.models.sevenf.review_format import group_hex_for_display, ski
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View


@dataclass(frozen=True)
class SevenFSignedCertificate:
    """ Shared by Root self-certification and Deputy cross-certification --
        both sign an arbitrary TBS body with the same Root key and export a
        complete assembled certificate. Threaded through view_args from
        SevenFConfirmSignRootCertView to SevenFRootCertSignedView to each
        flow's own export view, replacing this pair's former write/read of
        controller.sevenf_ceremony_data (7f-review-ceremony-data-untyped-
        shared-dict). root_cert_der is Deputy's own extra piece of context
        (the issuing Root's real certificate) -- None for Root self-cert,
        which has no separate issuer to carry. """
    public_key: bytes
    signature: bytes
    tbs_bytes: bytes
    root_cert_der: bytes | None = None
    key_index: int = 0  # the Root key index it was signed at, for the ski/pin screens after export

# Conservative, character-count-based page budget for a single review field's
# value -- found live 2026-09-27 (7F hardware walkthrough): the genesis-
# config's `message` field is arbitrary-length, coordinator-supplied text
# with no length limit enforced anywhere (Jorge's own call: an arbitrary cap
# invented on the device side would be a protocol decision, not a UI one --
# raise with Patrick separately if the ceremony protocol itself ever wants
# one). IconTextLine's value display has no scrolling primitive and no cap
# of its own -- a long-enough message silently renders past the canvas
# bounds with zero visual indication, which is a real no-blind-signing gap:
# the operator could approve a message they never actually saw in full.
# This is a character-count estimate, not exact pixel measurement -- same
# class of approximation as evm_screens.py's own _MAX_UNBROKEN_VALUE_CHARS.
# If it ever renders a page that doesn't quite fit some font/locale
# combination, the fix is tuning this constant down, not a correctness
# regression: every character is still shown on some page.
_MAX_CHARS_PER_REVIEW_PAGE = 180
# A warning field also shows its warning text, so its value gets less room;
# about three wrapped lines keeps the warning above the button (a grouped
# 128-hex dev-fund commitment hid its warning, found by rendering 2026-10-08).
_MAX_CHARS_PER_WARNING_PAGE = 75


def _paginate_value(value: str, max_chars: int = _MAX_CHARS_PER_REVIEW_PAGE) -> list[str]:
    """ Splits a field value into screen-sized pages, preferring to break
        after a space, but never letting a page exceed max_chars -- an
        unbroken run or embedded newlines must not push signed text off the
        screen. The pages joined are the value: no space is dropped at a cut,
        so a run of spaces in signed text stays countable (security review
        2026-10-08). """
    pages = []
    rest = value
    while len(rest) > max_chars:
        space = rest.rfind(" ", 0, max_chars)
        cut = space + 1 if space > 0 else max_chars
        pages.append(rest[:cut])
        rest = rest[cut:]
    pages.append(rest)
    return pages


def refuse_on_unexpected_error(handle_complete_scan):
    """ For every 7F scan's _handle_complete_scan: any error from decoding or
        parsing hostile input becomes the normal refusal screen, never the
        crash screen that clears history (security review 2026-10-08). """
    import functools
    import logging

    @functools.wraps(handle_complete_scan)
    def wrapper(self, *args, **kwargs):
        try:
            return handle_complete_scan(self, *args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- deliberate boundary
            logging.getLogger(__name__).warning("7F scan refused: %r", e)
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't use this QR: {}").format(e)))
    return wrapper


# The last review's fields and their pages: every page of one review is
# handed the same list, so it is split once, not once per page press (a long
# message made that quadratic; security review 2026-10-08).
_last_split: tuple[list, list] = ([], [])


def _review_pages(review_fields: list[ReviewField]) -> list[ReviewField]:
    """ One screen per page: long values split on word boundaries; a warning
        field's pages are shorter and each repeats the warning. """
    global _last_split
    if _last_split[0] is review_fields:
        return _last_split[1]
    pages = [
        ReviewField(label=field.label, value=chunk_value, is_warning=field.is_warning, warning_detail=field.warning_detail)
        for field in review_fields
        for chunk_value in _paginate_value(
            field.value,
            _MAX_CHARS_PER_WARNING_PAGE if field.is_warning and field.warning_detail else _MAX_CHARS_PER_REVIEW_PAGE,
        )
    ]
    _last_split = (review_fields, pages)
    return pages


# A refusal's reason can carry text from the refused input; the screen lays
# text out in time quadratic in its length (security review 2026-10-08).
_MAX_REASON_CHARS = 300


def _bounded(reason: str) -> str:
    return reason if len(reason) <= _MAX_REASON_CHARS else reason[:_MAX_REASON_CHARS] + "\u2026"



class SevenFUnsupportedArtefactView(View):
    """ Same role as evm_views.EvmUnsupportedSignRequestView -- a scanned
        artefact that claims to be a 7F ceremony payload but doesn't
        actually parse as one, or (via the optional `headline` override)
        parses fine but must still be refused for a different reason --
        e.g. a well-formed CertRequest whose subject_vk doesn't match this
        device's own derived key (the fail-closed refusal an adversarial
        security review required: "This request is for Root X, and this
        database holds Root Y", mirroring sf-wallet-gov's own hard refusal in
        sign_ops.rs validate_deputy_request).
        `headline` defaults to the original "Can't Parse This" wording so
        every existing call site is unaffected. """
    def __init__(self, reason: str, headline: str | None = None):
        super().__init__()
        self.reason = _bounded(reason)
        self.headline = headline if headline is not None else _("Can't Parse This")


    def run(self):
        from seedsigner.gui.screens import DireWarningScreen
        from seedsigner.gui.components import SeedSignerIconConstants
        self.run_screen(
            DireWarningScreen,
            title=_("Unsupported Artefact"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=self.headline,
            text=self.reason,
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, skip_current_view=True)



def subject_key_id_with_index(public_key: bytes, key_index: int) -> str:
    """ The ski as the device shows it, with the key index on its own line
        under it (7f-signing-support-key-index-selector). Its own line because
        "signing as Root CA, index 4294967295" runs off a 240px screen;
        rendered at the maximum index, 2026-10-08. """
    return group_hex_for_display(ski(public_key.hex())) + "\n" + _("index {}").format(key_index)


def key_index_review_field(chain_kind: ChainKind, key_index: int) -> ReviewField:
    """ The first review page of every Root-signed artefact: which key will
        sign, by index and full path, as sf-wallet-gov prints it ("signing as
        root <ski> (<path>)"). The path is one word wider than the screen at a
        long index, so it breaks before "ml-dsa". A warning when the index is
        not the default. """
    head, tail = root_path(chain_kind, key_index).split("ml-dsa/", 1)
    return ReviewField(
        label=_("Root key"),
        value=_("index {}").format(key_index) + "\n" + head + "\nml-dsa/" + tail,
        is_warning=key_index != 0,
        warning_detail=_("Not the default index 0") if key_index != 0 else "",
    )


def signing_refusal(error: Exception):
    """ The refusal for a signature the library would not produce. A failed
        self-check (as sf-wallet-gov's sign_checked) means the device computed
        a wrong signature: nothing is exported, and the device is suspect. """
    from seedsigner.models.sevenf._ffi import ErrCode
    if getattr(error, "code", None) == ErrCode.SIGNATURE_SELF_CHECK_FAILED:
        return Destination(SevenFUnsupportedArtefactView, view_args=dict(
            headline=_("Signature Check Failed"),
            reason=_("The new signature did not verify under its own key. Nothing was exported. "
                     "Do not use this device for the ceremony; tell the coordinator.")))
    return Destination(SevenFUnsupportedArtefactView, view_args=dict(
        headline=_("Not Signed"),
        reason=_("The signing library refused ({}). Nothing was exported.").format(error)))


def refuse_unless_signed_by_shown_key(signed_with: bytes, shown: bytes):
    """ Fail closed if the key that signed is not the key the confirm screen
        showed (a lost index would sign at 0 under a key shown at N). Returns
        a refusal Destination, or None when they match. """
    if signed_with == shown:
        return None
    return Destination(SevenFUnsupportedArtefactView, view_args=dict(
        headline=_("Key Mismatch"),
        reason=_("The signing key is not the key shown for confirmation. Nothing was exported; start again."),
    ))



class SevenFCertRequestReviewFieldView(View):
    """ Pages through a CertRequest's review fields one concern per screen --
        the no-blind-signing screen this project's adversarial plan-stage
        review (2026-09-28) found entirely missing from the original Root
        self-certification / Deputy cross-certification story filing
        (CRITICAL, confirmed independently by two reviewers). Mirrors
        _genesis.SevenFGenesisReviewFieldView's own pagination exactly (same
        _paginate_value() mechanism, same reason: any field's value could in
        principle grow long, and no-blind-signing means every field is shown
        in full, never silently truncated).

        Deliberately parameterized rather than hardcoded to one flow: Root
        self-certification, Deputy cross-certification, AND devfund-config
        signing all page through this same view, via each artifact's own
        review_fields() builder, but diverge on what happens after the
        operator confirms (a different sign call, a different export). Each
        call site supplies its own page_title and the View class + view_args
        to route to once every field has been shown -- this view does not
        itself call into any model module or perform any signing, keeping it
        reusable and testable in isolation. State is carried entirely through
        view_args (not controller.sevenf_ceremony_data, which the unrelated
        genesis-config flow already owns) so this view has no shared-state
        collision risk with that flow. """
    def __init__(
        self,
        review_fields: list[ReviewField],
        page_title: str,
        confirmed_destination: type,
        confirmed_view_args: dict | None = None,
        page_num: int = 0,
    ):
        super().__init__()
        self.review_fields = review_fields
        self.page_title = page_title
        self.confirmed_destination = confirmed_destination
        self.confirmed_view_args = confirmed_view_args or {}
        self.page_num = page_num
        self.chunks: list[ReviewField] = _review_pages(review_fields)

        if self.page_num >= len(self.chunks):
            raise Exception("Bug in 7F CertRequest review field paging")


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFReviewFieldScreen
        chunk = self.chunks[self.page_num]
        is_final_page = self.page_num == len(self.chunks) - 1

        selected_menu_num = self.run_screen(
            SevenFReviewFieldScreen,
            page_title=self.page_title,
            label_text=chunk.label,
            value_text=chunk.value,
            page_num=self.page_num,
            num_pages=len(self.chunks),
            is_final_page=is_final_page,
            is_warning=chunk.is_warning,
            warning_detail=chunk.warning_detail,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if is_final_page:
            return Destination(self.confirmed_destination, view_args=self.confirmed_view_args)
        else:
            return Destination(
                SevenFCertRequestReviewFieldView,
                view_args=dict(
                    review_fields=self.review_fields,
                    page_title=self.page_title,
                    confirmed_destination=self.confirmed_destination,
                    confirmed_view_args=self.confirmed_view_args,
                    page_num=self.page_num + 1,
                ),
            )



class SevenFConfirmSignRootCertView(View):
    """ Final review step for Root self-certification: confirms which chain
        and which Root CA address the signature will be attributed to (same
        confirmation content and same SevenFConfirmSignScreen as genesis
        signing -- confirming WHICH key signs is identical regardless of
        WHAT artefact it signs), then performs the actual signing. This is
        the ONLY caller permitted to pass confirmed=True for this flow, same
        contract as _genesis.SevenFConfirmSignView.

        Reuses root_ceremony.sign_with_root_ca() unmodified -- it already
        signs an arbitrary `message`, so signing a CertRequest's TBS bytes
        needs no new signing primitive, only a new caller. Builds a
        SevenFSignedCertificate on success, now including `tbs_bytes`
        itself (previously discarded here -- see
        docs/7f-integration/archive/root-self-cert-pkcs10-rework-plan.md §3 for why
        that was a real, already-shipped bug: a TBS whose serial/not_before
        are device-chosen can never be reconstructed downstream from a
        detached signature alone). `root_cert_der` is the Deputy flow's own
        extra piece of context (the issuing Root's real certificate,
        carried from _deputy_cert.SevenFScanRootCertificateView) -- None for
        Root self-cert, which has no separate issuer to carry. Closes the
        Deputy half of 7f-signing-support-detached-sig-export-unreconstructable
        (the Root half shipped in the PKCS#10 rework above).

        Shared by Root self-certification AND Deputy cross-certification
        (both sign an arbitrary TBS body with this same Root key) --
        `signed_view_args` is the one thing that differs between them (the
        success message's wording, and which export view follows), passed
        straight through to SevenFRootCertSignedView. """
    def __init__(self, seed: Seed, chain_kind: ChainKind, tbs_bytes: bytes, key_index: int, root_cert_der: bytes | None = None, signed_view_args: dict | None = None):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.tbs_bytes = tbs_bytes
        self.key_index = key_index
        self.root_cert_der = root_cert_der
        self.signed_view_args = signed_view_args or {}

        self.public_key = root_public_key(self.seed, self.chain_kind, key_index)
        self.subject_key_id = subject_key_id_with_index(self.public_key, key_index)


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFConfirmSignScreen
        selected_menu_num = self.run_screen(
            SevenFConfirmSignScreen,
            chain_kind_name=self.chain_kind.name.lower(),
            subject_key_id=self.subject_key_id,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Operator clicked "Sign" -- the one and only call site allowed to pass
        # confirmed=True for this flow (root_ceremony.sign_with_root_ca's own docstring).
        try:
            public_key, signature = root_ceremony.sign_with_root_ca(
                root_ceremony.seed_for_7f(self.seed),
                self.chain_kind,
                self.tbs_bytes,
                confirmed=True,
                index=self.key_index,
            )
        except MlDsaError as e:
            return signing_refusal(e)
        refused = refuse_unless_signed_by_shown_key(public_key, self.public_key)
        if refused:
            return refused
        certificate = SevenFSignedCertificate(
            public_key=public_key, signature=signature, tbs_bytes=self.tbs_bytes, root_cert_der=self.root_cert_der,
            key_index=self.key_index,
        )
        return Destination(
            SevenFRootCertSignedView,
            view_args=dict(self.signed_view_args, certificate=certificate),
        )



class SevenFRootCertSignedView(View):
    """ Success confirmation for Root self-certification AND Deputy cross-
        certification (both sign via SevenFConfirmSignRootCertView, which
        is itself artefact-agnostic -- see that class's own docstring).
        `title`/`text` default to the original Root self-cert wording so
        that flow's pre-existing behavior stays unchanged for callers that
        don't override them; the Deputy flow supplies its own.

        `export_destination` has NO default (changed 2026-10-04,
        7f-review-sevenf-views-py-split): it used to default to
        _genesis.SevenFExportView (the unrelated genesis pubkey/signed-
        config menu), kept only as a fallback neither of the two real
        callers (Root self-cert, Deputy cross-cert) ever relied on --
        confirmed by grep, no caller or test constructs this view without
        explicitly passing export_destination. The full-project adversarial
        review's modularity dimension flagged this as a latent hazard (a
        future third caller forgetting to override it would silently wrap
        a certificate-flow TBS/signature as a genesis-shaped RootSig JSON
        export); making it required removes that hazard outright, and
        avoids this shared module needing to import the genesis-specific
        _genesis.SevenFExportView just for a default nothing used.

        `certificate` (added 2026-10-04, 7f-review-ceremony-data-untyped-
        shared-dict) carries the just-signed SevenFSignedCertificate through
        to `export_destination`, replacing the former read of
        controller.sevenf_ceremony_data that each export view used to do
        itself. """
    def __init__(self, export_destination: type, certificate: SevenFSignedCertificate, title: str | None = None, text: str | None = None):
        super().__init__()
        self.title = title if title is not None else _("Root Certificate Signed")
        self.text = text if text is not None else _("This Root's own certificate has been signed and is ready to export.")
        self.export_destination = export_destination
        self.certificate = certificate


    def run(self):
        from seedsigner.gui.screens.screen import ButtonOption, LargeIconStatusScreen
        self.run_screen(
            LargeIconStatusScreen,
            title=self.title,
            show_back_button=False,
            status_headline=_("Success!"),
            text=self.text,
            button_data=[ButtonOption("OK")],
        )
        return Destination(self.export_destination, view_args=dict(certificate=self.certificate))



class SevenFNotA7FPhraseView(View):
    """ Shown instead of any 7F flow for a seed 7fchain would not derive from
        (not 24 English BIP-39 words; sf-keytree phrase_file.rs ROOT_WORD_COUNT). """
    def __init__(self, reason: str):
        super().__init__()
        self.reason = _bounded(reason)


    def run(self):
        from seedsigner.gui.screens import DireWarningScreen
        self.run_screen(
            DireWarningScreen,
            title=_("7F"),
            show_back_button=False,
            status_headline=_("Not a 7F phrase"),
            text=self.reason,
            button_data=[ButtonOption("OK")],
        )
        return Destination(BackStackView)



def root_public_key(seed: Seed, chain_kind: ChainKind, key_index: int) -> bytes:
    """ This seed's Root key at `key_index`: 7fchain's
        root/<network>/<index>/ml-dsa/v1, from a 7F phrase only (seed_for_7f). """
    return root_ceremony.derive_root_ceremony_keys(
        root_ceremony.seed_for_7f(seed), chain_kind, index=key_index).root_ca.public_key


def refuse_if_already_signed(public_key: bytes, key_index: int, signer_vks: tuple[str, ...], what: str):
    """ sf-wallet-gov's "already signed. Nothing to do", or None. The refusal
        replaces the calling view, which has no screen of its own: Back from
        the refusal must not land on it and show the same refusal again. """
    if not config_json.already_signed_by(signer_vks, public_key):
        return None
    return Destination(SevenFAlreadySignedView, view_args=dict(
        what=what, subject_key_id=subject_key_id_with_index(public_key, key_index)), skip_current_view=True)



class SevenFAlreadySignedView(View):
    """ sf-wallet-gov's refusal (sign_ops.rs validate_genesis/validate_devfund):
        "this Root has already signed this definition. Nothing to do". Shown
        before the review, once the signing key is known. """
    def __init__(self, what: str, subject_key_id: str):
        super().__init__()
        self.what = what
        self.subject_key_id = subject_key_id


    def run(self):
        from seedsigner.gui.screens import WarningScreen
        self.run_screen(
            WarningScreen,
            title=_("7F"),
            show_back_button=False,
            status_headline=_("Already signed"),
            text=_("This Root key ({}) has already signed this {}. Nothing to do.").format(self.subject_key_id, self.what),
            button_data=[ButtonOption("OK")],
        )
        return Destination(BackStackView)
