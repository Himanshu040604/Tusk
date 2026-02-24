"""IAM Policy Sentinel - Offline IAM Policy Validation Tool.

This package provides offline validation of AWS IAM policies using a local
SQLite database of IAM actions, resources, and condition keys.
"""

from .constants import (
    SCHEMA_VERSION,
    DEFAULT_ACCOUNT_ID,
    DEFAULT_REGION,
    READ_PREFIXES,
    WRITE_PREFIXES,
    ADMIN_PREFIXES,
    KNOWN_SERVICES,
    SECURITY_CRITICAL_SERVICES,
    REGION_LESS_GLOBAL_SERVICES,
    EXIT_SUCCESS,
    EXIT_ISSUES_FOUND,
    EXIT_INVALID_ARGS,
    EXIT_IO_ERROR,
    DEFAULT_DB_PATH,
    DEFAULT_INVENTORY_PATH,
    load_known_services,
)

from .database import (
    Database,
    DatabaseError,
    Service,
    Action,
    ResourceType,
    ConditionKey,
)

from .parser import (
    PolicyParser,
    PolicyParserError,
    Policy,
    Statement,
    ValidationResult,
    ValidationTier,
)

from .inventory import (
    ResourceInventory,
    InventoryError,
    Resource,
)

from .analyzer import (
    IntentMapper,
    RiskAnalyzer,
    DangerousPermissionChecker,
    CompanionPermissionDetector,
    HITLSystem,
    AccessLevel,
    RiskSeverity,
    IntentMapping,
    RiskFinding,
    CompanionPermission,
    HITLDecision,
)

from .rewriter import (
    PolicyRewriter,
    RewriteConfig,
    RewriteResult,
    RewriteChange,
)

from .formatters import (
    TextFormatter,
    JsonFormatter,
    MarkdownFormatter,
)

from .self_check import (
    SelfCheckValidator,
    Pipeline,
    SelfCheckResult,
    PipelineResult,
    PipelineConfig,
    CheckFinding,
    CheckSeverity,
    CheckVerdict,
)

__version__ = "0.5.0"

__all__ = [
    # Constants
    "SCHEMA_VERSION",
    "DEFAULT_ACCOUNT_ID",
    "DEFAULT_REGION",
    "READ_PREFIXES",
    "WRITE_PREFIXES",
    "ADMIN_PREFIXES",
    "KNOWN_SERVICES",
    "SECURITY_CRITICAL_SERVICES",
    "REGION_LESS_GLOBAL_SERVICES",
    "EXIT_SUCCESS",
    "EXIT_ISSUES_FOUND",
    "EXIT_INVALID_ARGS",
    "EXIT_IO_ERROR",
    "DEFAULT_DB_PATH",
    "DEFAULT_INVENTORY_PATH",
    "load_known_services",
    # Database
    "Database",
    "DatabaseError",
    "Service",
    "Action",
    "ResourceType",
    "ConditionKey",
    # Parser
    "PolicyParser",
    "PolicyParserError",
    "Policy",
    "Statement",
    "ValidationResult",
    "ValidationTier",
    # Inventory
    "ResourceInventory",
    "InventoryError",
    "Resource",
    # Analyzer
    "IntentMapper",
    "RiskAnalyzer",
    "DangerousPermissionChecker",
    "CompanionPermissionDetector",
    "HITLSystem",
    "AccessLevel",
    "RiskSeverity",
    "IntentMapping",
    "RiskFinding",
    "CompanionPermission",
    "HITLDecision",
    # Rewriter
    "PolicyRewriter",
    "RewriteConfig",
    "RewriteResult",
    "RewriteChange",
    # Formatters
    "TextFormatter",
    "JsonFormatter",
    "MarkdownFormatter",
    # Self-Check
    "SelfCheckValidator",
    "Pipeline",
    "SelfCheckResult",
    "PipelineResult",
    "PipelineConfig",
    "CheckFinding",
    "CheckSeverity",
    "CheckVerdict",
    # Version
    "__version__",
]
