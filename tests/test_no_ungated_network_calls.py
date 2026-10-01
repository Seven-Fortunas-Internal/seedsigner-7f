"""Enforces the airgap at the source level: application code must never import a
network-capable module unless the import site is explicitly gated. See
docs/security/software-enforced-airgap-plan.md (L2) in the diy-seedsigner repo --
per Jorge's 2026-09-27 reframe, physical WiFi/BT chip removal is no longer the
control the airgap claim depends on (anyone can flash this build onto their own
stock Pi Zero 2 W), so this has to be an enforced, systematic rule, not a single
runtime guard someone remembered to add once.

AST-based, not grep: distinguishes a real `import socket` from the string
"socket" appearing in a comment, docstring, or variable name, and can tell
whether a flagged import sits inside a function already decorated with
helpers.version.not_allowed_in_seedsigner_os -- the existing runtime guard that
raises NotAllowedInSeedSignerOS if Settings.HOSTNAME == Settings.SEEDSIGNER_OS.

As of 2026-09-30 there is exactly one real network-capable import in the whole
tree: helpers/version.py's _fetch_latest_seedsigner_release_tag (import
urllib.request; from http.client import HTTPResponse), both inside that
@not_allowed_in_seedsigner_os-decorated function, so this test passes with an
empty ALLOWLIST today. A future call site that can't carry that decorator
(e.g. a bare module-level import) can be added to ALLOWLIST with a reason
instead -- see its docstring below.
"""
import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "seedsigner"

# Only the submodules that can actually originate a network call -- not the
# whole top-level package (e.g. urllib.parse/urllib.error do no network I/O
# and are legitimate to use freely; flagging bare "urllib" would force
# allowlisting those too, for no security benefit).
NETWORK_MODULES = {
    "socket",
    "urllib.request",
    "requests",
    "http.client",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc.client",
}

GUARD_DECORATOR_NAME = "not_allowed_in_seedsigner_os"

# {"path/relative/to/seedsigner-7f-repo-root.py:lineno": "one-line reason"}
# Use only for a call site that genuinely cannot carry the
# @not_allowed_in_seedsigner_os decorator (e.g. a bare module-level import
# rather than one local to a guardable function). Empty today -- see module
# docstring.
ALLOWLIST: dict[str, str] = {}


class _NetworkImportVisitor(ast.NodeVisitor):
    """Walks one file's AST, tracking whether the current position is inside a
    function decorated with @not_allowed_in_seedsigner_os, and records any
    network-capable import found outside of one."""

    def __init__(self):
        self.violations: list[int] = []
        self._guard_depth = 0

    @staticmethod
    def _decorator_names(decorator_list: list[ast.expr]) -> set[str]:
        names = set()
        for d in decorator_list:
            if isinstance(d, ast.Name):
                names.add(d.id)
            elif isinstance(d, ast.Attribute):
                names.add(d.attr)
        return names

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        guarded = GUARD_DECORATOR_NAME in self._decorator_names(node.decorator_list)
        if guarded:
            self._guard_depth += 1
        self.generic_visit(node)
        if guarded:
            self._guard_depth -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_function(node)

    def _flag_if_network(self, node: ast.Import | ast.ImportFrom, names: set[str]):
        if not (names & NETWORK_MODULES):
            return
        if self._guard_depth > 0:
            return
        self.violations.append(node.lineno)

    def visit_Import(self, node: ast.Import):
        self._flag_if_network(node, {alias.name for alias in node.names})
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self._flag_if_network(node, {node.module or ""})
        self.generic_visit(node)


def _find_violations() -> list[str]:
    violations = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        visitor = _NetworkImportVisitor()
        visitor.visit(tree)
        rel_path = str(path.relative_to(REPO_ROOT))
        for lineno in visitor.violations:
            key = f"{rel_path}:{lineno}"
            if key in ALLOWLIST:
                continue
            violations.append(
                f"{key}: network-capable import with no @{GUARD_DECORATOR_NAME} "
                f"guard and no ALLOWLIST entry"
            )
    return violations


def test_no_ungated_network_calls():
    violations = _find_violations()
    assert not violations, (
        "Airgap enforcement failure (docs/security/software-enforced-airgap-plan.md): "
        "found network-capable import(s) outside any @not_allowed_in_seedsigner_os "
        "guard and not in this test's ALLOWLIST:\n" + "\n".join(violations)
    )


# --- Detector self-tests: prove the visitor actually catches what it claims to,
# not just that it happens to pass against today's codebase. Synthetic source
# snippets, not real files -- a regression in the detector itself (e.g. the
# guard-depth tracking silently matching nothing) would otherwise look
# identical to "no violations" and this test file would pass for the wrong
# reason forever. ---

def _violations_in_source(source: str) -> list[int]:
    visitor = _NetworkImportVisitor()
    visitor.visit(ast.parse(source))
    return visitor.violations


def test_detector_flags_an_unguarded_top_level_import():
    assert _violations_in_source("import socket\n") == [1]


def test_detector_flags_an_unguarded_import_inside_a_plain_function():
    source = "def f():\n    import urllib.request\n"
    assert _violations_in_source(source) == [2]


def test_detector_allows_an_import_inside_a_guarded_function():
    source = (
        "@not_allowed_in_seedsigner_os\n"
        "def f():\n"
        "    import urllib.request\n"
        "    from http.client import HTTPResponse\n"
    )
    assert _violations_in_source(source) == []


def test_detector_allows_an_import_inside_a_guarded_method_via_attribute_decorator():
    # Mirrors the real call site: @classmethod stacked with
    # @not_allowed_in_seedsigner_os, decorator referenced as a bare name here
    # but this form (module.not_allowed_in_seedsigner_os) must also match.
    source = (
        "class V:\n"
        "    @classmethod\n"
        "    @helpers.not_allowed_in_seedsigner_os\n"
        "    def f(cls):\n"
        "        import socket\n"
    )
    assert _violations_in_source(source) == []


def test_detector_ignores_non_network_imports():
    source = "import json\nimport urllib.parse\nfrom urllib.error import URLError\n"
    assert _violations_in_source(source) == []


def test_detector_does_not_leak_guard_state_across_sibling_functions():
    # A violation in an unguarded function defined AFTER a guarded one must
    # still be caught -- proves _guard_depth is decremented back on exit,
    # not left permanently "on" by a prior guarded function in the same file.
    source = (
        "@not_allowed_in_seedsigner_os\n"
        "def guarded():\n"
        "    import socket\n"
        "\n"
        "def unguarded():\n"
        "    import socket\n"
    )
    assert _violations_in_source(source) == [6]


def test_find_violations_flags_a_real_file_end_to_end(tmp_path, monkeypatch):
    fake_src_root = tmp_path / "src" / "seedsigner"
    fake_src_root.mkdir(parents=True)
    (fake_src_root / "bad.py").write_text("import socket\n")
    import tests.test_no_ungated_network_calls as mod
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "SRC_ROOT", fake_src_root)

    violations = mod._find_violations()

    assert len(violations) == 1
    assert "src/seedsigner/bad.py:1" in violations[0]


def test_find_violations_respects_the_allowlist_end_to_end(tmp_path, monkeypatch):
    fake_src_root = tmp_path / "src" / "seedsigner"
    fake_src_root.mkdir(parents=True)
    (fake_src_root / "bad.py").write_text("import socket\n")
    import tests.test_no_ungated_network_calls as mod
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "SRC_ROOT", fake_src_root)
    monkeypatch.setitem(mod.ALLOWLIST, "src/seedsigner/bad.py:1", "test-only entry")

    assert mod._find_violations() == []
