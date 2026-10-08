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
from seedsigner.models.sevenf import root_ceremony
from seedsigner.models.sevenf.constants import ChainKind
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
    """ Splits a field value into screen-sized pages, preferring to break at
        a space, but never letting a page exceed max_chars -- an unbroken run
        or embedded newlines must not push signed text off the screen
        (security review 2026-10-08). """
    pages = []
    rest = value
    while len(rest) > max_chars:
        cut = rest.rfind(" ", 0, max_chars + 1)
        if cut <= 0:
            cut = max_chars
        pages.append(rest[:cut].rstrip(" "))
        rest = rest[cut:].lstrip(" ")
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


def _review_pages(review_fields: list[ReviewField]) -> list[ReviewField]:
    """ One screen per page: long values split on word boundaries; a warning
        field's pages are shorter and each repeats the warning. """
    return [
        ReviewField(label=field.label, value=chunk_value, is_warning=field.is_warning, warning_detail=field.warning_detail)
        for field in review_fields
        for chunk_value in _paginate_value(
            field.value,
            _MAX_CHARS_PER_WARNING_PAGE if field.is_warning and field.warning_detail else _MAX_CHARS_PER_REVIEW_PAGE,
        )
    ]


class SevenFUnsupportedArtefactView(View):
    """ Same role as evm_views.EvmUnsupportedSignRequestView -- a scanned
        artefact that claims to be a 7F ceremony payload but doesn't
        actually parse as one, or (via the optional `headline` override)
        parses fine but must still be refused for a different reason --
        e.g. a well-formed CertRequest whose subject_vk doesn't match this
        device's own derived key (the fail-closed refusal an adversarial
        security review required: "This request is for Root X, and this
        database holds Root Y", mirroring sf-root.rs's own hard refusal).
        `headline` defaults to the original "Can't Parse This" wording so
        every existing call site is unaffected. """
    def __init__(self, reason: str, headline: str | None = None):
        super().__init__()
        self.reason = reason
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
        docs/7f-integration/root-self-cert-pkcs10-rework-plan.md §3 for why
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
    def __init__(self, seed: Seed, chain_kind: ChainKind, tbs_bytes: bytes, root_cert_der: bytes | None = None, signed_view_args: dict | None = None):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.tbs_bytes = tbs_bytes
        self.root_cert_der = root_cert_der
        self.signed_view_args = signed_view_args or {}

        keys = root_ceremony.derive_root_ceremony_keys(self.seed.seed_bytes, self.chain_kind)
        self.root_ca_address = keys.root_ca.address
        self.subject_key_id = group_hex_for_display(ski(keys.root_ca.public_key.hex()))


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFConfirmSignScreen
        selected_menu_num = self.run_screen(
            SevenFConfirmSignScreen,
            chain_kind_name=self.chain_kind.name.lower(),
            address=self.root_ca_address,
            subject_key_id=self.subject_key_id,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Operator clicked "Sign" -- the one and only call site allowed to pass
        # confirmed=True for this flow (root_ceremony.sign_with_root_ca's own docstring).
        public_key, signature = root_ceremony.sign_with_root_ca(
            self.seed.seed_bytes,
            self.chain_kind,
            self.tbs_bytes,
            confirmed=True,
        )
        certificate = SevenFSignedCertificate(
            public_key=public_key, signature=signature, tbs_bytes=self.tbs_bytes, root_cert_der=self.root_cert_der,
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
