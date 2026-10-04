"""
    7fchain root-key ceremony UI, split by ceremony flow 2026-10-04
    (7f-review-sevenf-views-py-split, found by the full-project
    adversarial review's Python-code-quality and modularity dimensions):
    the former monolithic sevenf_views.py held four independent flows plus
    shared infrastructure in one 1,106-line module, well over this
    project's own 800-line soft ceiling. This package re-exports every
    public name the old flat module did, under the same `sevenf_views`
    import path -- every existing `from seedsigner.views import
    sevenf_views` / `from seedsigner.views.sevenf_views import X` call
    site (seed_views.py, tests/test_sevenf_views.py) works unchanged; only
    this package's own internal organization is new.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py, evm_views.py <-> evm_screens.py);
    see gui/screens/sevenf_screens.py for the paired Screen classes.

    Module map:
      _common.py       Shared infra: pagination, the "didn't parse"
                        refusal screen, the generic CertRequest-shaped
                        review pager, and the confirm-sign/signed pair
                        shared by Root self-cert and Deputy cross-cert.
      _genesis.py       Genesis-config signing
                        (7f-signing-support-root-ceremony-ui-wizard).
      _root_cert.py     Root self-certification
                        (docs/7f-integration/root-self-cert-pkcs10-rework-plan.md).
      _deputy_cert.py   Deputy cross-certification
                        (docs/7f-integration/deputy-cross-cert-pkcs10-rework-plan.md).
      _devfund.py       Devfund-config signing (R11).

    tests/test_sevenf_views.py's own 8 test classes already map 1:1 onto
    these same four flows (TestSevenFGenesisReviewFlow,
    TestSevenFRootSelfCertificationFlow, TestSevenFDeputyCrossCertificationFlow,
    TestSevenFDevFundConfigSigningFlow, plus shared/cross-cutting ones) --
    confirmed by the modularity-dimension reviewer as a ready-made split
    template; the test file itself is left as one file for now (not part
    of this story's scope), still importing `sevenf_views` as a whole and
    referencing e.g. `sevenf_views.SevenFScanGenesisConfigView` exactly as
    it always has.
"""
from ._common import (
    SevenFCertRequestReviewFieldView,
    SevenFConfirmSignRootCertView,
    SevenFRootCertSignedView,
    SevenFUnsupportedArtefactView,
    _paginate_value,
    _MAX_CHARS_PER_REVIEW_PAGE,
)
from ._genesis import (
    SevenFConfirmSignView,
    SevenFExportPubkeyQRView,
    SevenFExportSignedConfigQRView,
    SevenFExportView,
    SevenFGenesisReviewFieldView,
    SevenFGenesisReviewStartView,
    SevenFGenesisSignedView,
    SevenFScanGenesisConfigView,
)
from ._root_cert import (
    SevenFExportRootCertQRView,
    SevenFSelectChainKindForRootSelfCertView,
)
from ._deputy_cert import (
    SevenFExportDeputyCertQRView,
    SevenFScanDeputyCsrView,
    SevenFScanRootCertificateView,
    SevenFSelectChainKindForDeputyCrossCertView,
)
from ._devfund import (
    SevenFConfirmSignDevFundView,
    SevenFDevFundConfigSignedView,
    SevenFExportSignedDevFundConfigQRView,
    SevenFScanDevFundConfigView,
)

__all__ = [
    "SevenFCertRequestReviewFieldView",
    "SevenFConfirmSignDevFundView",
    "SevenFConfirmSignRootCertView",
    "SevenFConfirmSignView",
    "SevenFDevFundConfigSignedView",
    "SevenFExportDeputyCertQRView",
    "SevenFExportPubkeyQRView",
    "SevenFExportRootCertQRView",
    "SevenFExportSignedConfigQRView",
    "SevenFExportSignedDevFundConfigQRView",
    "SevenFExportView",
    "SevenFGenesisReviewFieldView",
    "SevenFGenesisReviewStartView",
    "SevenFGenesisSignedView",
    "SevenFRootCertSignedView",
    "SevenFScanDeputyCsrView",
    "SevenFScanDevFundConfigView",
    "SevenFScanGenesisConfigView",
    "SevenFScanRootCertificateView",
    "SevenFSelectChainKindForDeputyCrossCertView",
    "SevenFSelectChainKindForRootSelfCertView",
    "SevenFUnsupportedArtefactView",
]
