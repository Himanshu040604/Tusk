"""IAM Policy parser and validator.

This module provides JSON parsing, validation, and three-tier action classification
for IAM policies.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, List, Dict, Any, Optional, Set
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from .constants import KNOWN_SERVICES as _KNOWN_SERVICES

if TYPE_CHECKING:
    from .database import Database


class ValidationTier(Enum):
    """Three-tier classification for IAM actions.

    TIER_1_VALID: Action exists in database
    TIER_2_UNKNOWN: Not in database but plausible format
    TIER_3_INVALID: Invalid format or impossible action name
    """
    TIER_1_VALID = "VALID"
    TIER_2_UNKNOWN = "UNKNOWN"
    TIER_3_INVALID = "INVALID"


class PolicyParserError(Exception):
    """Base exception for policy parsing errors."""
    pass


@dataclass
class ValidationResult:
    """Result of action validation.

    Attributes:
        action: The action name being validated
        tier: Classification tier (VALID, UNKNOWN, INVALID)
        reason: Human-readable explanation
        access_level: Access level if known (List, Read, Write, etc.)
        suggestions: List of suggested corrections if applicable
        confidence: Classification confidence (1.0=DB match, 0.6=known svc, 0.5=wildcard, 0.0=invalid)
    """
    action: str
    tier: ValidationTier
    reason: str
    access_level: Optional[str] = None
    suggestions: Optional[List[str]] = None
    confidence: float = 1.0

    def __post_init__(self):
        """Initialize suggestions list if not provided."""
        if self.suggestions is None:
            self.suggestions = []


@dataclass
class Statement:
    """IAM Policy Statement data model.

    Attributes:
        sid: Statement ID
        effect: Allow or Deny
        actions: List of actions
        resources: List of resource ARNs
        conditions: Condition block if present
        principals: Principal block if present (for resource policies)
        not_actions: NotAction block if present
        not_resources: NotResource block if present
    """
    effect: str
    actions: List[str]
    resources: List[str]
    sid: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    principals: Optional[Dict[str, Any]] = None
    not_actions: Optional[List[str]] = None
    not_resources: Optional[List[str]] = None


@dataclass
class Policy:
    """IAM Policy data model.

    Attributes:
        version: Policy version (usually '2012-10-17')
        statements: List of policy statements
        id: Optional policy ID
    """
    version: str
    statements: List[Statement]
    id: Optional[str] = None


class PolicyParser:
    """Parser for IAM policy JSON documents.

    Provides validation and three-tier action classification.
    """

    # Valid action name pattern: service:ActionName
    ACTION_PATTERN = re.compile(r'^[a-z0-9\-]+:[A-Za-z0-9*]+$')

    # Pattern for action names (must start with uppercase or *, no spaces)
    ACTION_NAME_PATTERN = re.compile(r'^[A-Z*][A-Za-z0-9*]*$')

    def __init__(self, database: Optional[Database] = None):
        """Initialize parser.

        Two-layer service resolution:
            Layer 1 (truth): Database service prefixes
            Layer 2 (fallback): JSON cache (data/known_services.json)
        Lenient mode when both are unavailable.

        Args:
            database: Optional Database instance for Tier 1 validation.
                Also used to load service prefixes (Layer 1).
        """
        self.database = database
        self.known_services: Set[str] = set()
        self._services_source: str = "none"

        # Layer 1: DB service prefixes (truth)
        if self.database:
            try:
                db_prefixes = {s.service_prefix for s in self.database.get_services()}
                if db_prefixes:
                    self.known_services = db_prefixes
                    self._services_source = "database"
            except (sqlite3.Error, OSError):
                pass  # DB failed, fall through to JSON cache

        # Layer 2: JSON cache (fallback or supplement)
        json_services = set(_KNOWN_SERVICES)
        if json_services:
            if self._services_source == "database":
                # Merge JSON into DB set (DB is truth, JSON supplements)
                self.known_services |= json_services
            else:
                # No DB available, JSON is primary
                self.known_services = json_services
                self._services_source = "json_cache"

        # If both empty, _services_source stays "none" (lenient mode)

    def parse_policy(self, policy_json: str) -> Policy:
        """Parse IAM policy JSON string.

        Args:
            policy_json: JSON string containing IAM policy

        Returns:
            Policy object

        Raises:
            PolicyParserError: If JSON is invalid or required fields missing
        """
        try:
            data = json.loads(policy_json)
        except json.JSONDecodeError as e:
            raise PolicyParserError(f"Invalid JSON: {e}")

        return self._parse_policy_dict(data)

    def parse_policy_file(self, file_path: Path) -> Policy:
        """Parse IAM policy from file.

        Args:
            file_path: Path to JSON policy file

        Returns:
            Policy object

        Raises:
            PolicyParserError: If file cannot be read or parsed
        """
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return self.parse_policy(content)
        except FileNotFoundError:
            raise PolicyParserError(f"Policy file not found: {file_path}")
        except PolicyParserError:
            raise  # Don't re-wrap our own errors
        except Exception as e:
            raise PolicyParserError(f"Error reading policy file: {e}")

    def parse_policy_yaml(self, yaml_string: str) -> Policy:
        """Parse IAM policy from a YAML string.

        Args:
            yaml_string: YAML string containing IAM policy.

        Returns:
            Policy object.

        Raises:
            PolicyParserError: If pyyaml is not installed or YAML is invalid.
        """
        if yaml is None:
            raise PolicyParserError(
                "PyYAML is required for YAML input. "
                "Install it with: pip install pyyaml"
            )
        try:
            data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise PolicyParserError(f"Invalid YAML: {e}")

        if not isinstance(data, dict):
            raise PolicyParserError(
                "YAML content must be a mapping, got "
                f"{type(data).__name__}"
            )

        return self._parse_policy_dict(data)

    def parse_policy_auto(self, content: str, fmt: str) -> Policy:
        """Parse IAM policy, dispatching by format.

        Args:
            content: Raw policy text (JSON or YAML).
            fmt: Format identifier — ``"json"`` or ``"yaml"``.

        Returns:
            Policy object.

        Raises:
            PolicyParserError: On parse errors or unsupported format.
        """
        if fmt == "yaml":
            return self.parse_policy_yaml(content)
        if fmt == "json":
            return self.parse_policy(content)
        raise PolicyParserError(f"Unsupported input format: {fmt}")

    def _parse_policy_dict(self, data: Dict[str, Any]) -> Policy:
        """Parse policy dictionary.

        Args:
            data: Policy dictionary

        Returns:
            Policy object

        Raises:
            PolicyParserError: If required fields missing
        """
        if 'Version' not in data:
            raise PolicyParserError("Policy missing required 'Version' field")

        if 'Statement' not in data:
            raise PolicyParserError("Policy missing required 'Statement' field")

        version = data['Version']
        statement_data = data['Statement']

        # Statement can be a single dict or list of dicts
        if isinstance(statement_data, dict):
            statement_data = [statement_data]
        elif not isinstance(statement_data, list):
            raise PolicyParserError("Statement must be an object or array")

        statements = [self._parse_statement(stmt) for stmt in statement_data]

        return Policy(
            version=version,
            statements=statements,
            id=data.get('Id')
        )

    def _parse_statement(self, stmt: Dict[str, Any]) -> Statement:
        """Parse statement dictionary.

        Args:
            stmt: Statement dictionary

        Returns:
            Statement object

        Raises:
            PolicyParserError: If required fields missing
        """
        if 'Effect' not in stmt:
            raise PolicyParserError("Statement missing required 'Effect' field")

        effect = stmt['Effect']
        if effect not in ['Allow', 'Deny']:
            raise PolicyParserError(f"Invalid Effect: {effect}")

        # Get actions (Action or NotAction)
        actions = []
        not_actions = None

        if 'Action' in stmt:
            action_data = stmt['Action']
            if not isinstance(action_data, (str, list)):
                raise PolicyParserError(
                    "Action must be a string or list of strings"
                )
            actions = [action_data] if isinstance(action_data, str) else action_data
            if isinstance(action_data, list) and not all(isinstance(a, str) for a in actions):
                raise PolicyParserError(
                    "All Action entries must be strings"
                )
        elif 'NotAction' in stmt:
            not_action_data = stmt['NotAction']
            if not isinstance(not_action_data, (str, list)):
                raise PolicyParserError(
                    "NotAction must be a string or list of strings"
                )
            not_actions = [not_action_data] if isinstance(not_action_data, str) else not_action_data
            if isinstance(not_action_data, list) and not all(isinstance(a, str) for a in not_actions):
                raise PolicyParserError(
                    "All NotAction entries must be strings"
                )
        else:
            raise PolicyParserError("Statement missing 'Action' or 'NotAction'")

        # Get resources (Resource or NotResource)
        resources = []
        not_resources = None

        if 'Resource' in stmt:
            resource_data = stmt['Resource']
            if not isinstance(resource_data, (str, list)):
                raise PolicyParserError(
                    "Resource must be a string or list of strings"
                )
            resources = [resource_data] if isinstance(resource_data, str) else resource_data
            if isinstance(resource_data, list) and not all(isinstance(r, str) for r in resources):
                raise PolicyParserError(
                    "All Resource entries must be strings"
                )
        elif 'NotResource' in stmt:
            not_resource_data = stmt['NotResource']
            if not isinstance(not_resource_data, (str, list)):
                raise PolicyParserError(
                    "NotResource must be a string or list of strings"
                )
            not_resources = [not_resource_data] if isinstance(not_resource_data, str) else not_resource_data
            if isinstance(not_resource_data, list) and not all(isinstance(r, str) for r in not_resources):
                raise PolicyParserError(
                    "All NotResource entries must be strings"
                )
        else:
            raise PolicyParserError("Statement missing 'Resource' or 'NotResource'")

        return Statement(
            sid=stmt.get('Sid'),
            effect=effect,
            actions=actions,
            resources=resources,
            conditions=stmt.get('Condition'),
            principals=stmt.get('Principal'),
            not_actions=not_actions,
            not_resources=not_resources
        )

    def validate_policy(self, policy: Policy) -> List[ValidationResult]:
        """Validate all actions in policy.

        Args:
            policy: Policy object to validate

        Returns:
            List of ValidationResult objects
        """
        results = []
        seen_actions = set()

        for statement in policy.statements:
            # Validate both Action and NotAction entries
            actions_to_validate = list(statement.actions)
            if statement.not_actions:
                actions_to_validate.extend(statement.not_actions)
            for action in actions_to_validate:
                # Expand wildcards
                expanded = self._expand_action_wildcard(action)

                for expanded_action in expanded:
                    if expanded_action not in seen_actions:
                        seen_actions.add(expanded_action)
                        result = self.classify_action(expanded_action)
                        results.append(result)

        return results

    def classify_action(self, action: str) -> ValidationResult:
        """Classify action using three-tier system.

        Tier 1 (VALID): Action exists in database
        Tier 2 (UNKNOWN): Not in database but plausible format
        Tier 3 (INVALID): Invalid format or impossible action name

        Args:
            action: IAM action name (service:action)

        Returns:
            ValidationResult with classification
        """
        # Handle wildcards
        if action == '*' or action == '*:*':
            return ValidationResult(
                action=action,
                tier=ValidationTier.TIER_2_UNKNOWN,
                reason="Wildcard action grants all permissions",
                confidence=0.5,
            )

        # Basic format validation
        if not self.ACTION_PATTERN.match(action):
            return ValidationResult(
                action=action,
                tier=ValidationTier.TIER_3_INVALID,
                reason="Invalid action format. Expected 'service:ActionName'",
                suggestions=self._suggest_corrections(action),
                confidence=0.0,
            )

        # Split into service and action name
        parts = action.split(':', 1)
        service_prefix = parts[0]
        action_name = parts[1]

        # Check if contains wildcard
        if '*' in action:
            # Validate wildcard pattern
            if not self._is_valid_wildcard(action):
                return ValidationResult(
                    action=action,
                    tier=ValidationTier.TIER_3_INVALID,
                    reason="Invalid wildcard pattern",
                    confidence=0.0,
                )

            # Wildcard with known service is plausible
            service_known = service_prefix in self.known_services
            if not service_known and self.database:
                try:
                    service_known = self.database.service_exists(service_prefix)
                except Exception:
                    pass
            if service_known:
                return ValidationResult(
                    action=action,
                    tier=ValidationTier.TIER_2_UNKNOWN,
                    reason=f"Wildcard action for known service '{service_prefix}'",
                    confidence=0.5,
                )

            return ValidationResult(
                action=action,
                tier=ValidationTier.TIER_3_INVALID,
                reason=f"Unknown service prefix: {service_prefix}",
                suggestions=[f"{svc}:{action_name}" for svc in self._find_similar_services(service_prefix)],
                confidence=0.0,
            )

        # Tier 1: Check database if available
        if self.database:
            try:
                if self.database.action_exists(action):
                    db_action = self.database.get_action(service_prefix, action_name)
                    return ValidationResult(
                        action=action,
                        tier=ValidationTier.TIER_1_VALID,
                        reason="Action found in IAM database",
                        access_level=db_action.access_level if db_action else None,
                        confidence=1.0,
                    )
            except Exception:
                pass  # DB query failed, fall through to Tier 2

        # Tier 2: Plausible but not in database
        if self._is_plausible_action(service_prefix, action_name):
            reason = self._get_tier2_reason(service_prefix)
            return ValidationResult(
                action=action,
                tier=ValidationTier.TIER_2_UNKNOWN,
                reason=reason,
                confidence=0.6,
            )

        # Tier 3: Invalid
        return ValidationResult(
            action=action,
            tier=ValidationTier.TIER_3_INVALID,
            reason=self._get_invalid_reason(service_prefix, action_name),
            suggestions=self._suggest_corrections(action),
            confidence=0.0,
        )

    def _is_plausible_action(self, service_prefix: str, action_name: str) -> bool:
        """Check if action format is plausible.

        Args:
            service_prefix: Service prefix
            action_name: Action name

        Returns:
            True if action format is plausible
        """
        # Service must be known or exist in database
        service_known = service_prefix in self.known_services
        if not service_known and self.database:
            try:
                service_known = self.database.service_exists(service_prefix)
            except Exception:
                pass

        # In lenient mode (no services loaded), accept valid format
        if not service_known and self._services_source == "none":
            service_known = True

        if not service_known:
            return False

        # Action name must follow AWS naming convention
        # Uppercase start, alphanumeric, no spaces
        return bool(self.ACTION_NAME_PATTERN.match(action_name))

    def _get_tier2_reason(self, service_prefix: str) -> str:
        """Get Tier 2 reason string based on services source.

        Args:
            service_prefix: Service prefix being classified.

        Returns:
            Human-readable reason distinguishing cache vs lenient mode.
        """
        if self._services_source == "database":
            return "Action not in database but format is plausible. May be new or custom."
        elif self._services_source == "json_cache":
            return (
                f"Service '{service_prefix}' recognized (cached). "
                "Action verification requires database."
            )
        else:
            return "No service data available. Action format is valid."

    def _get_invalid_reason(self, service_prefix: str, action_name: str) -> str:
        """Get reason why action is invalid.

        Args:
            service_prefix: Service prefix
            action_name: Action name

        Returns:
            Human-readable reason
        """
        service_known = service_prefix in self.known_services
        if not service_known and self.database:
            try:
                service_known = self.database.service_exists(service_prefix)
            except Exception:
                pass
        if not service_known:
            return f"Unknown AWS service: {service_prefix}"

        if not self.ACTION_NAME_PATTERN.match(action_name):
            return f"Invalid action name format: {action_name}. Must start with uppercase letter."

        return "Action does not match any known AWS IAM action"

    def _is_valid_wildcard(self, action: str) -> bool:
        """Validate wildcard action pattern.

        Args:
            action: Action with wildcard

        Returns:
            True if wildcard pattern is valid
        """
        # service:* is valid
        # service:Get* is valid
        # service:*Object is valid
        # *:* is valid
        # Invalid: service:Get*Put, multiple stars

        if action == '*:*':
            return True

        parts = action.split(':', 1)
        if len(parts) != 2:
            return False

        service_prefix, action_pattern = parts

        # Service prefix must be a valid lowercase identifier (not *)
        # Note: *:* is handled above, so * prefix is invalid here
        if not re.match(r'^[a-z0-9\-]+$', service_prefix):
            return False

        # Action pattern validation
        # Only one wildcard allowed, at start or end
        star_count = action_pattern.count('*')
        if star_count > 1:
            return False

        if star_count == 1:
            # Must be at start or end
            if not (action_pattern.startswith('*') or action_pattern.endswith('*')):
                return False

        return True

    def _expand_action_wildcard(self, action: str) -> List[str]:
        """Expand wildcard actions if database available.

        Args:
            action: Action potentially with wildcard

        Returns:
            List of expanded actions (or original if no expansion)
        """
        if '*' not in action:
            return [action]

        if not self.database:
            return [action]

        # Handle full wildcard
        if action == '*' or action == '*:*':
            return [action]

        # Handle service:* pattern
        parts = action.split(':', 1)
        if len(parts) != 2:
            return [action]

        service_prefix, action_pattern = parts

        # service:*
        if action_pattern == '*':
            actions = self.database.get_actions_by_service(service_prefix)
            expanded = [f"{service_prefix}:{a.action_name}" for a in actions]
            return expanded if expanded else [action]

        # Prefix/suffix matching: service:Get*, service:*Object
        if action_pattern.startswith('*'):
            suffix = action_pattern[1:]
            actions = self.database.get_actions_by_service(service_prefix)
            expanded = [
                f"{service_prefix}:{a.action_name}"
                for a in actions
                if a.action_name.endswith(suffix)
            ]
            return expanded if expanded else [action]
        elif action_pattern.endswith('*'):
            prefix = action_pattern[:-1]
            actions = self.database.get_actions_by_service(service_prefix)
            expanded = [
                f"{service_prefix}:{a.action_name}"
                for a in actions
                if a.action_name.startswith(prefix)
            ]
            return expanded if expanded else [action]

        return [action]

    def _suggest_corrections(self, action: str) -> List[str]:
        """Suggest corrections for invalid action.

        Args:
            action: Invalid action name

        Returns:
            List of suggested corrections
        """
        suggestions = []

        # Try to parse service and action
        if ':' in action:
            parts = action.split(':', 1)
            service_prefix = parts[0]
            action_name = parts[1] if len(parts) > 1 else ''

            # Suggest similar services
            similar_services = self._find_similar_services(service_prefix)
            for svc in similar_services[:3]:
                suggestions.append(f"{svc}:{action_name}")

            # Fix common action name issues
            if action_name and not action_name[0].isupper() and action_name[0].isalpha():
                # Capitalize first letter
                fixed_name = action_name[0].upper() + action_name[1:]
                suggestions.append(f"{service_prefix}:{fixed_name}")

        return suggestions

    def _find_similar_services(self, service_prefix: str) -> List[str]:
        """Find similar service prefixes.

        Args:
            service_prefix: Service prefix to match

        Returns:
            List of similar service prefixes
        """
        similar = []

        # Use cached database service prefixes (loaded once in __init__)
        db_service_prefixes = sorted(self.known_services)

        # Try different matching strategies
        # 1. Exact prefix match (first N characters)
        for prefix_len in range(min(len(service_prefix), 3), 0, -1):
            match_prefix = service_prefix[:prefix_len]

            # Check known services
            for svc in self.known_services:
                if svc.startswith(match_prefix) and svc not in similar:
                    similar.append(svc)

            # Check database services
            for svc_prefix in db_service_prefixes:
                if svc_prefix.startswith(match_prefix) and svc_prefix not in similar:
                    similar.append(svc_prefix)

            # If we found matches, return them
            if similar:
                return sorted(similar)[:5]

        # 2. If no prefix matches, try character similarity
        first_char = service_prefix[0] if service_prefix else ''
        for svc in self.known_services:
            if svc and svc[0] == first_char and svc not in similar:
                similar.append(svc)

        for svc_prefix in db_service_prefixes:
            if svc_prefix and svc_prefix[0] == first_char and svc_prefix not in similar:
                similar.append(svc_prefix)

        return sorted(similar)[:5]

    def extract_actions(self, policy: Policy) -> Set[str]:
        """Extract all unique actions from policy.

        Includes both Action and NotAction entries.

        Args:
            policy: Policy object

        Returns:
            Set of action names
        """
        actions = set()

        for statement in policy.statements:
            for action in statement.actions:
                actions.add(action)
            if statement.not_actions:
                for action in statement.not_actions:
                    actions.add(action)

        return actions

    def get_policy_summary(self, policy: Policy) -> Dict[str, Any]:
        """Generate summary of policy.

        Args:
            policy: Policy object

        Returns:
            Dictionary with policy summary
        """
        all_actions = self.extract_actions(policy)
        validation_results = self.validate_policy(policy)

        tier1_count = sum(1 for r in validation_results if r.tier == ValidationTier.TIER_1_VALID)
        tier2_count = sum(1 for r in validation_results if r.tier == ValidationTier.TIER_2_UNKNOWN)
        tier3_count = sum(1 for r in validation_results if r.tier == ValidationTier.TIER_3_INVALID)

        return {
            'version': policy.version,
            'statement_count': len(policy.statements),
            'total_actions': len(all_actions),
            'valid_actions': tier1_count,
            'unknown_actions': tier2_count,
            'invalid_actions': tier3_count,
            'has_wildcards': any('*' in action for action in all_actions),
            'has_deny_statements': any(stmt.effect == 'Deny' for stmt in policy.statements)
        }
