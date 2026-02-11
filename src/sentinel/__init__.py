"""IAM Policy Sentinel - Offline IAM Policy Validation Tool.

This package provides offline validation of AWS IAM policies using a local
SQLite database of IAM actions, resources, and condition keys.
"""

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

__version__ = "0.2.0"

__all__ = [
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
    # Version
    "__version__",
]
