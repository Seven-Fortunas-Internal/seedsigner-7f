"""
    ReviewField -- one field on a paged no-blind-signing review screen,
    used across every chain's signing flow. Lives here, outside the
    `chains` package, specifically so `models/*` modules can import it
    without pulling in `seedsigner.chains.__init__`'s package-level side
    effect (`_register_builtin_plugins()`, which imports every registered
    chain plugin, each of which imports back into `models/sevenf/*`).

    MOVED HERE 2026-10-03 (7f-review-models-chains-import-cycle, found by
    the full-project adversarial review's modularity dimension): this type
    used to live in `chains/base.py`, so `models/sevenf/{cert_request,
    genesis_config,devfund_config}.py`'s `from seedsigner.chains.base
    import ReviewField` had to import the `seedsigner.chains` PACKAGE
    first (Python always runs a package's `__init__.py` before any of its
    submodules become importable) -- which eagerly imports
    `chains.sevenf.plugin`, which imports back into `models.sevenf.
    genesis_config`. This only worked by accident of import style
    (`chains/sevenf/plugin.py` does `from seedsigner.models.sevenf import
    genesis_config` -- a whole-module import that only reads attributes at
    call time -- never `from ...genesis_config import <name>`, which would
    have failed with an AttributeError the moment the cycle's second leg
    hit a partially-initialized module). `chains/base.py` re-exports
    `ReviewField` from here so every existing `from seedsigner.chains.base
    import ReviewField` call site (EVM's plugin/views, the chain-plugin
    template) keeps working unchanged.
"""
from dataclasses import dataclass


@dataclass
class ReviewField:
    """
        One field on a paged no-blind-signing review screen. `is_warning` marks a
        hard-stop item (e.g. an unlimited approval) that review UI should render
        distinctly from an ordinary informational field, not just another line item.
    """
    label: str
    value: str
    is_warning: bool = False
    warning_detail: str = ""
