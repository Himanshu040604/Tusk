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

__version__ = "0.1.0"

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
    # Version
    "__version__",
]
