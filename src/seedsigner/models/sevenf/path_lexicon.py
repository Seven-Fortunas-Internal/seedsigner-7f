"""
    Derivation paths are checked by 7fchain's own rules: crates/sf-keytree/src/path.rs,
    ported verbatim into firmware/mldsa7f (src/path.rs) and called through the
    FFI. 7fchain's lexicon requires exactly this: "The device must apply the same
    rules, and must do so by calling this code over FFI rather than
    reimplementing it" (docs/derivation-path-lexicon.md). This module keeps no
    copy of the rules; the Rust derivation also validates every path itself
    (derive.rs), so this is the place a caller gets 7fchain's message, not a
    second gate.

        <role>/<chain-kind>/[<chain-id>/]<index>/<algorithm>/v<N>[/<leaf>]
"""


class PathLexiconError(Exception):
    """ A path 7fchain's rules refuse; the message is 7fchain's. """


def validate(path: str) -> None:
    """ Raise PathLexiconError, with 7fchain's message, unless `path` is valid. """
    from seedsigner.models.sevenf import mldsa  # mldsa imports this module

    refusal = mldsa.path_refusal(path)
    if refusal is not None:
        raise PathLexiconError(refusal)
