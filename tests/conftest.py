"""
    A test that fails only because the 7F Rust library (firmware/mldsa7f, in the
    parent diy-seedsigner repo) is not built here is reported as skipped, with
    that reason: this repo's own CI has no copy of it. The parent repo's CI
    builds the library and runs this whole suite against it, where nothing is
    skipped for this reason. Any other failure stays a failure.
"""
import os

import pytest

_LIBRARY_MISSING = "mldsa7f shared library not found"


# Set where the library is built (the parent repo's CI): then nothing skips
# for its absence, and a missing library fails.
REQUIRED = os.environ.get("SEVENF_REQUIRE_MLDSA7F") == "1"


def _caused_by_missing_library(error: BaseException | None) -> bool:
    """ The error is the loader's own, or was raised from it (__cause__); an
        unrelated error raised while handling it does not count. """
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, FileNotFoundError) and _LIBRARY_MISSING in str(error):
            return True
        error = error.__cause__
    return False


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if REQUIRED:
        return
    if report.failed and call.excinfo is not None and _caused_by_missing_library(call.excinfo.value):
        report.outcome = "skipped"
        report.longrepr = (str(item.path), item.location[1] or 0,
                           "Skipped: firmware/mldsa7f is not built here; the parent repo's CI runs this test")
