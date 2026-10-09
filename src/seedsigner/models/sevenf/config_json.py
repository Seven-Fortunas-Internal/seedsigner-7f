"""
    The JSON rules of 7fchain's serde types for the coordinator's genesis and
    dev-fund files (sf-core src/genesis_config.rs: GenesisConfig,
    DevFundConfig, RootSig, read through serde_json), shared by
    genesis_config.py and devfund_config.py. Each check takes the caller's
    error class, so a refusal reads as that file's own error. Checked against
    sf-core's own types (tests/test_sevenf_device_limits.py).

    Error messages show at most a short excerpt of a refused value: the text
    is untrusted, and reaches the operator's screen.
"""
import json

U64_MAX = 0xFFFFFFFFFFFFFFFF
_SHOWN_MAX = 40

# sf-core RootSig: the fields of each `signatures` entry.
ROOT_SIG_FIELDS = frozenset({"signer_vk", "sig"})


def shown(value) -> str:
    """ repr() of an untrusted value, cut to a few dozen characters. """
    text = repr(value)
    return text if len(text) <= _SHOWN_MAX else text[:_SHOWN_MAX] + "..."


def has_surrogate(text: str) -> bool:
    """ A lone UTF-16 surrogate, from a JSON escape such as "\\ud800": serde_json
        refuses it in any string it reads (a known field, or any key). """
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


class JsonObject(dict):
    """ A parsed JSON object that had a repeated key. """
    duplicates: frozenset = frozenset()


def _object(pairs: list):
    seen, duplicates = set(), set()
    for key, _ in pairs:
        if has_surrogate(key):
            raise ValueError("a key holds a lone surrogate escape")
        (duplicates if key in seen else seen).add(key)
    if not duplicates:
        return dict(pairs)                 # the usual case: no per-object extra
    obj = JsonObject(pairs)
    obj.duplicates = frozenset(duplicates)
    return obj


def _parse_int(digits: str):
    # serde_json reads -0 as a float, which no integer field accepts; an
    # ignored value may be anything.
    return -0.0 if digits == "-0" else int(digits)


def _refuse_constant(name: str):
    raise ValueError(f"non-standard JSON literal {name}")


def load_object(data: bytes, error: type[Exception], what: str) -> dict:
    """ The file's top-level JSON object, refusing what serde_json refuses for
        any type: invalid UTF-8, NaN/Infinity, integers past Python's digit
        limit, lone surrogates in keys. Repeated keys are recorded per object
        for refuse_duplicate_fields(), since whether a repeat is an error
        depends on the type reading that object. """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise error(f"payload is not valid UTF-8: {e}") from e
    try:
        obj = json.loads(text, parse_constant=_refuse_constant, parse_int=_parse_int, object_pairs_hook=_object)
    except (json.JSONDecodeError, RecursionError, ValueError) as e:
        # RecursionError: Python's json is recursive descent, so ~100k levels
        # of "[" raise it rather than JSONDecodeError; still a clean refusal.
        raise error(f"payload is not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise error(f"expected a JSON object for the {what}, got {type(obj).__name__}")
    return obj


def refuse_duplicate_fields(obj: dict, known: frozenset, where: str, error: type[Exception]) -> None:
    """ serde_json's rule for 7fchain's types (no deny_unknown_fields): a
        repeated KNOWN field is an error ("duplicate field `x`"); a repeated
        unknown key is ignored. """
    repeated = sorted(getattr(obj, "duplicates", frozenset()) & known)
    if repeated:
        raise error(f"duplicate field `{repeated[0]}` in {where}")


def require_u64(obj: dict, key: str, where: str, error: type[Exception]) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= U64_MAX):
        raise error(f"{where}{key} must be a non-negative 64-bit integer, got {shown(value)}")
    return value


def require_string(obj: dict, key: str, where: str, error: type[Exception]) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise error(f"{where}{key} must be a string, got {type(value).__name__}")
    if has_surrogate(value):
        raise error(f"{where}{key} holds a lone surrogate escape")
    return value


def signer_vks(obj: dict, error: type[Exception]) -> tuple[str, ...]:
    """ The `signer_vk` of each entry of the optional `signatures` list
        (#[serde(default)]). Shape-checked as serde does, although canonical
        bytes never cover them: sf-core fails to read the whole file when an
        entry is not a RootSig (both fields required strings). """
    signatures = obj.get("signatures", [])
    if not isinstance(signatures, list):
        raise error(f"signatures must be an array, got {type(signatures).__name__}")
    found = []
    for i, entry in enumerate(signatures):
        where = f"signatures[{i}]"
        if not isinstance(entry, dict):
            raise error(f"{where} must be an object, got {type(entry).__name__}")
        refuse_duplicate_fields(entry, ROOT_SIG_FIELDS, where, error)
        found.append(require_string(entry, "signer_vk", where + ".", error))
        require_string(entry, "sig", where + ".", error)
    return tuple(found)


def already_signed_by(vks: tuple[str, ...], public_key: bytes) -> bool:
    """ sf-wallet-gov's "this Root has already signed this definition. Nothing
        to do" (sign_ops.rs validate_genesis/validate_devfund): a non-empty
        signer_vk equal to this key's, ignoring hex case. Another Root's
        signature, or a keyless record, never blocks. """
    mine = public_key.hex()
    return any(vk and vk.lower() == mine for vk in vks)
