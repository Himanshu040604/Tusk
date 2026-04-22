"""IAM Policy Sentinel - Offline IAM Policy Validation Tool.

This package provides offline validation of AWS IAM policies using a local
SQLite database of IAM actions, resources, and condition keys.

Import-time discipline (H25).  This module used to eagerly import every
sub-module (parser, analyzer, rewriter, self_check, formatters, ...).
That pulled the full module graph on `import sentinel` and made
`sentinel --version` / `sentinel info` blow the <200ms Phase 1 startup
budget.  We now expose the same public names via PEP 562
:func:`__getattr__` — the first access materializes the target module,
subsequent accesses hit the module's own binding cache.
"""

# M20: Python runtime version guard — MUST stay at the very top, BEFORE
# any third-party import.  Duplicates __main__.py's guard to catch
# `import sentinel` in library-API contexts as well as the CLI.
import sys

if sys.version_info < (3, 11):
    sys.stderr.write(
        f"Sentinel requires Python 3.11+; found "
        f"{sys.version_info.major}.{sys.version_info.minor}.\n"
        f"Recreate venv: 'uv venv --python 3.11 && uv sync'\n"
    )
    sys.exit(3)

from typing import Any

__version__ = "0.5.0"

# Mapping of lazily-exposed public name -> (submodule, attribute).  When a
# caller does `from sentinel import RiskAnalyzer`, the first access walks
# this table, imports sentinel.analyzer, and returns RiskAnalyzer.  All
# subsequent `sentinel.RiskAnalyzer` references hit the module's own cache.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # Database
    "Database": ("sentinel.database", "Database"),
    "DatabaseError": ("sentinel.database", "DatabaseError"),
    "Service": ("sentinel.database", "Service"),
    "Action": ("sentinel.database", "Action"),
    "ResourceType": ("sentinel.database", "ResourceType"),
    "ConditionKey": ("sentinel.database", "ConditionKey"),
    # Parser
    "PolicyParser": ("sentinel.parser", "PolicyParser"),
    "PolicyParserError": ("sentinel.parser", "PolicyParserError"),
    "Policy": ("sentinel.parser", "Policy"),
    "Statement": ("sentinel.parser", "Statement"),
    "ValidationResult": ("sentinel.parser", "ValidationResult"),
    "ValidationTier": ("sentinel.parser", "ValidationTier"),
    # Inventory
    "ResourceInventory": ("sentinel.inventory", "ResourceInventory"),
    "InventoryError": ("sentinel.inventory", "InventoryError"),
    "Resource": ("sentinel.inventory", "Resource"),
    # Analyzer
    "IntentMapper": ("sentinel.analyzer", "IntentMapper"),
    "RiskAnalyzer": ("sentinel.analyzer", "RiskAnalyzer"),
    "DangerousPermissionChecker": (
        "sentinel.analyzer",
        "DangerousPermissionChecker",
    ),
    "CompanionPermissionDetector": (
        "sentinel.analyzer",
        "CompanionPermissionDetector",
    ),
    "HITLSystem": ("sentinel.analyzer", "HITLSystem"),
    "AccessLevel": ("sentinel.analyzer", "AccessLevel"),
    "RiskSeverity": ("sentinel.analyzer", "RiskSeverity"),
    "IntentMapping": ("sentinel.analyzer", "IntentMapping"),
    "RiskFinding": ("sentinel.analyzer", "RiskFinding"),
    "CompanionPermission": ("sentinel.analyzer", "CompanionPermission"),
    "HITLDecision": ("sentinel.analyzer", "HITLDecision"),
    # Rewriter
    "PolicyRewriter": ("sentinel.rewriter", "PolicyRewriter"),
    "RewriteConfig": ("sentinel.rewriter", "RewriteConfig"),
    "RewriteResult": ("sentinel.rewriter", "RewriteResult"),
    "RewriteChange": ("sentinel.rewriter", "RewriteChange"),
    # Formatters
    "TextFormatter": ("sentinel.formatters", "TextFormatter"),
    "JsonFormatter": ("sentinel.formatters", "JsonFormatter"),
    "MarkdownFormatter": ("sentinel.formatters", "MarkdownFormatter"),
    # Self-Check
    "SelfCheckValidator": ("sentinel.self_check", "SelfCheckValidator"),
    "Pipeline": ("sentinel.self_check", "Pipeline"),
    "SelfCheckResult": ("sentinel.self_check", "SelfCheckResult"),
    "PipelineResult": ("sentinel.self_check", "PipelineResult"),
    "PipelineConfig": ("sentinel.self_check", "PipelineConfig"),
    "CheckFinding": ("sentinel.self_check", "CheckFinding"),
    "CheckSeverity": ("sentinel.self_check", "CheckSeverity"),
    "CheckVerdict": ("sentinel.self_check", "CheckVerdict"),
    # Constants still exported for backwards compat; lightweight module.
    "SCHEMA_VERSION": ("sentinel.constants", "SCHEMA_VERSION"),
    "DEFAULT_ACCOUNT_ID": ("sentinel.constants", "DEFAULT_ACCOUNT_ID"),
    "DEFAULT_REGION": ("sentinel.constants", "DEFAULT_REGION"),
    "READ_PREFIXES": ("sentinel.constants", "READ_PREFIXES"),
    "WRITE_PREFIXES": ("sentinel.constants", "WRITE_PREFIXES"),
    "ADMIN_PREFIXES": ("sentinel.constants", "ADMIN_PREFIXES"),
    "SECURITY_CRITICAL_SERVICES": (
        "sentinel.constants",
        "SECURITY_CRITICAL_SERVICES",
    ),
    "REGION_LESS_GLOBAL_SERVICES": (
        "sentinel.constants",
        "REGION_LESS_GLOBAL_SERVICES",
    ),
    "EXIT_SUCCESS": ("sentinel.exit_codes", "EXIT_SUCCESS"),
    "EXIT_ISSUES_FOUND": ("sentinel.exit_codes", "EXIT_ISSUES_FOUND"),
    "EXIT_INVALID_ARGS": ("sentinel.exit_codes", "EXIT_INVALID_ARGS"),
    "EXIT_IO_ERROR": ("sentinel.exit_codes", "EXIT_IO_ERROR"),
    "EXIT_CRITICAL_FINDING": ("sentinel.exit_codes", "EXIT_CRITICAL_FINDING"),
    "DEFAULT_DB_PATH": ("sentinel.constants", "DEFAULT_DB_PATH"),
    "DEFAULT_INVENTORY_PATH": ("sentinel.constants", "DEFAULT_INVENTORY_PATH"),
    "load_known_services": ("sentinel.constants", "load_known_services"),
}


def __getattr__(name: str) -> Any:  # PEP 562
    """Resolve a lazy export on first access.

    Unknown names raise ``AttributeError`` per PEP 562 convention — the
    import system falls back to ``ImportError`` for ``from sentinel import
    <missing>`` patterns, which is what callers expect.
    """
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'sentinel' has no attribute {name!r}")
    module_name, attr_name = target
    import importlib

    module = importlib.import_module(module_name)
    value = getattr(module, attr_name)
    # Cache on the module so subsequent lookups skip __getattr__.
    globals()[name] = value
    return value


def __dir__() -> list[str]:  # PEP 562 companion
    return sorted(set(list(_LAZY_EXPORTS.keys()) + ["__version__"]))


__all__ = list(_LAZY_EXPORTS.keys()) + ["__version__"]
