"""5-level CLI exit code scheme (§ 7.4).

Existing codes 0/1/2/3 preserve their legacy meanings (POSIX shell convention
for code 2 is honored).  Code 4 is NEW — it fires specifically when the
pipeline surfaces at least one CRITICAL or HIGH-severity finding, giving
scripts a crisp boolean "bad policy detected" signal without needing to
parse JSON.

Backwards-compat note:  Pre-migration Sentinel conflated all findings into
code 1.  Scripts using ``[[ $? -eq 1 ]]`` to catch critical findings must
update to ``[[ $? -eq 1 || $? -eq 4 ]]``.  Document in CHANGELOG when v0.4.0
is cut.
"""

from __future__ import annotations

from typing import Final

#: No findings; policy is clean.
EXIT_SUCCESS: Final[int] = 0

#: At least one finding, all WARNING or below (narrowed from legacy semantics).
EXIT_ISSUES_FOUND: Final[int] = 1

#: Invalid CLI arguments — POSIX convention.
EXIT_INVALID_ARGS: Final[int] = 2

#: Sentinel crashed (bad input, missing DB, network failure beyond retries,
#: unwritable filesystem, migration failure).  Formerly ``EXIT_IO_ERROR``;
#: semantics widened in v0.4.0.
EXIT_IO_ERROR: Final[int] = 3

#: At least one CRITICAL or HIGH-severity finding.  NEW in v0.4.0.
EXIT_CRITICAL_FINDING: Final[int] = 4

__all__ = [
    "EXIT_SUCCESS",
    "EXIT_ISSUES_FOUND",
    "EXIT_INVALID_ARGS",
    "EXIT_IO_ERROR",
    "EXIT_CRITICAL_FINDING",
]
