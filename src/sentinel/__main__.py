"""Allow running as ``python -m sentinel``."""

# M20: Python runtime version guard — MUST stay at the very top, BEFORE
# any third-party import.  Catches pip-fallback users (H18) on pip < 23.1
# who bypass `requires-python` metadata.
import sys

if sys.version_info < (3, 11):
    sys.stderr.write(
        f"Sentinel requires Python 3.11+; found "
        f"{sys.version_info.major}.{sys.version_info.minor}.\n"
        f"Recreate venv: 'uv venv --python 3.11 && uv sync'\n"
    )
    sys.exit(3)

from .cli import main  # noqa: E402 — must follow the version guard

if __name__ == "__main__":
    main()
