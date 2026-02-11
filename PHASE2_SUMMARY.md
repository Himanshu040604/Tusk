# IAM Policy Sentinel - Phase 2 Complete

## Phase 2: Core Analysis (Risk Engine)

**Status**: [DONE] COMPLETE
**Date**: 2026-02-12
**Test Results**: 115/115 tests passing (100%)
**Code Coverage**: 87% overall, 98% for analyzer.py

---

## Deliverables Summary

### 1. Intent-to-Access-Level Mapper (`IntentMapper`)

Maps natural language developer intent to AWS access levels and specific actions.

**Features**:
- Natural language parsing with keyword detection
- Maps to 5 AWS access levels: List, Read, Write, Permissions management, Tagging
- Service extraction from intent strings
- Database integration for action lookup
- Confidence scoring
- Detailed explanation generation

**Supported Intent Patterns**:
```python
"read-only" → List + Read
"read-write" → List + Read + Write
"write-only" → Write
"list-only" → List
"admin/full" → All access levels
"deploy/ci-cd" → Write + Tagging
```

**Example Usage**:
```python
from src.sentinel.analyzer import IntentMapper

mapper = IntentMapper(database)
result = mapper.map_intent("read-only access to S3")

# Result:
# - access_levels: {List, Read}
# - services: {'s3'}
# - actions: ['s3:GetObject', 's3:ListBucket']
# - confidence: 1.0
```

---

### 2. Risk Detection Engine (`RiskAnalyzer`)

Comprehensive security risk analysis for IAM policies.

**Detection Capabilities**:

#### Wildcard Detection
- Full wildcard (`*`, `*:*`) → CRITICAL
- Service wildcard (`s3:*`) → HIGH/CRITICAL
- Prefix/suffix wildcards (`s3:Get*`) → MEDIUM
- IAM/STS/Organizations wildcards → CRITICAL severity

#### Privilege Escalation
Detects 20+ privilege escalation actions including:
- `iam:PassRole`
- `iam:CreatePolicyVersion`
- `iam:AttachRolePolicy`
- `lambda:UpdateFunctionCode`
- `cloudformation:CreateStack`
- And more...

#### Data Exfiltration Risks
- `s3:GetObject` patterns
- `secretsmanager:GetSecretValue`
- `ssm:GetParameter`
- `kms:Decrypt`
- Snapshot operations

#### Infrastructure Destruction
- Delete/Terminate/Drop patterns
- Critical resource deletions (buckets, tables, databases)

#### Permissions Management
- Policy creation/modification actions
- Trust policy updates
- Policy attachment operations

#### Dangerous Combinations
- `iam:PassRole` + `lambda:CreateFunction` → Privilege escalation
- `iam:PassRole` + `ec2:RunInstances` → Instance profile abuse
- `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` → Policy takeover

#### Cross-Statement Redundancy
- Detects when wildcards make specific actions redundant
- Service-level redundancy analysis

**Example Usage**:
```python
from src.sentinel.analyzer import RiskAnalyzer

analyzer = RiskAnalyzer(database)
findings = analyzer.analyze_actions([
    'iam:PassRole',
    'lambda:CreateFunction',
    's3:*'
])

# Returns RiskFinding objects with:
# - risk_type: e.g., "DANGEROUS_COMBINATION"
# - severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
# - description: Human-readable explanation
# - remediation: Suggested fixes
# - additional_context: Extra metadata
```

---

### 3. Dangerous Permission Checker (`DangerousPermissionChecker`)

Specialized checker for high-risk permissions with resource context.

**Features**:
- Single action analysis
- Resource-aware severity escalation
- Wildcard resource detection
- Contextual risk assessment

**Example Usage**:
```python
from src.sentinel.analyzer import DangerousPermissionChecker

checker = DangerousPermissionChecker(database)

# Wildcard resource escalates severity
findings = checker.check_action('iam:PassRole', resource='*')
# Returns CRITICAL findings

# Specific resource has lower severity
findings = checker.check_action('iam:PassRole', resource='arn:aws:iam::123456789012:role/MyRole')
# Returns HIGH findings
```

---

### 4. Companion Permission Detector (`CompanionPermissionDetector`)

Identifies missing companion permissions required for actions to function correctly.

**Built-in Rules**:

#### Lambda Execution
- `lambda:InvokeFunction` requires:
  - `logs:CreateLogGroup`
  - `logs:CreateLogStream`
  - `logs:PutLogEvents`

#### VPC Lambda
- `lambda:CreateFunction` in VPC requires:
  - `ec2:CreateNetworkInterface`
  - `ec2:DescribeNetworkInterfaces`
  - `ec2:DeleteNetworkInterface`

#### KMS-Encrypted Resources
- `s3:GetObject` with KMS requires:
  - `kms:Decrypt`
- `s3:PutObject` with KMS requires:
  - `kms:GenerateDataKey`
  - `kms:Decrypt`

#### SQS Consumer
- `sqs:ReceiveMessage` requires:
  - `sqs:DeleteMessage`
  - `sqs:GetQueueAttributes`
  - `sqs:ChangeMessageVisibility`

#### DynamoDB Streams
- `dynamodb:GetRecords` requires:
  - `dynamodb:GetShardIterator`
  - `dynamodb:DescribeStream`
  - `dynamodb:ListStreams`

**Example Usage**:
```python
from src.sentinel.analyzer import CompanionPermissionDetector

detector = CompanionPermissionDetector(database)
actions = ['lambda:InvokeFunction']
missing = detector.detect_missing_companions(actions)

# Returns CompanionPermission objects:
# - primary_action: 'lambda:InvokeFunction'
# - companion_actions: ['logs:CreateLogGroup', ...]
# - reason: Why these are needed
# - severity: Impact if missing
```

---

### 5. Human-in-the-Loop System (`HITLSystem`)

Validation system for Tier 2 (unknown) actions with decision tracking.

**Features**:
- Tier 2 action flagging
- Assumption validation
- Decision recording
- Approval history tracking
- Statistical analysis

**Example Usage**:
```python
from src.sentinel.analyzer import HITLSystem

hitl = HITLSystem()

# Flag Tier 2 action for review
assumptions = ["New AWS service", "Plausible format"]
approved = hitl.flag_tier2_action('newservice:GetData', assumptions)

# Record decisions
hitl.record_decision(
    action='verified:Action',
    tier='TIER_2_UNKNOWN',
    approved=True,
    comment='Verified with AWS documentation'
)

# Get statistics
stats = hitl.get_approval_stats()
# Returns: total_reviews, approved, rejected, approval_rate
```

---

## Test Coverage

### Test File: `tests/test_analyzer.py`

**50 tests organized into 6 test classes**:

#### TestIntentMapper (10 tests)
- Read-only, read-write, write-only intent mapping
- List-only and admin access mapping
- Deployment intent mapping
- Database action lookup
- Default to read-only for unknown intents
- Multiple service detection
- Explanation generation

#### TestRiskAnalyzer (16 tests)
- Full wildcard detection (CRITICAL)
- Service wildcard detection (HIGH/CRITICAL)
- IAM wildcard detection (CRITICAL)
- Privilege escalation detection
- Multiple escalation actions
- Data exfiltration risks
- Secrets access detection
- Destruction capability detection
- Permissions management detection
- Dangerous combination detection (Lambda, EC2, Policy)
- Redundancy detection (full and service wildcards)
- Safe action validation
- Wildcard severity assessment

#### TestDangerousPermissionChecker (3 tests)
- Wildcard resource severity escalation
- Specific resource checks
- Severity escalation logic

#### TestCompanionPermissionDetector (7 tests)
- Lambda CloudWatch Logs detection
- Lambda logs present validation
- SQS consumer lifecycle permissions
- KMS decrypt for S3
- Companion suggestions
- Unknown action handling
- DynamoDB Streams permissions
- Complete permission set validation

#### TestHITLSystem (8 tests)
- Tier 2 action flagging
- Decision recording (approved/rejected)
- Decision history retrieval
- Empty statistics handling
- Statistics with decisions
- History clearing
- Multiple flag calls

#### TestIntegration (6 tests)
- Full analysis pipeline
- Intent to risk analysis
- Companion detection with intent
- HITL with risk findings
- Comprehensive policy analysis

---

## Code Coverage Analysis

```
Name                        Stmts   Miss  Cover
-------------------------------------------------
src/sentinel/__init__.py        5      0   100%
src/sentinel/analyzer.py      255      4    98%
src/sentinel/database.py      147      0   100%
src/sentinel/parser.py        231     20    91%
src/sentinel/inventory.py     103     72    30%
-------------------------------------------------
TOTAL                         741     96    87%
```

**Phase 2 Module Coverage**: 98% (analyzer.py)
Only 4 lines uncovered (edge cases in error handling)

---

## Technical Specifications Met

### Intent Keywords Mapping [DONE]
All specified patterns implemented:
- Read-only patterns: read, get, describe, view
- Read-write patterns: modify, update, manage
- Write-only patterns: create, put, upload
- List-only patterns: list, enumerate
- Admin patterns: admin, full, full-access
- Deployment patterns: deploy, ci/cd
- Tagging and permissions patterns

### Dangerous Permission Patterns [DONE]
Comprehensive detection:
- 20+ privilege escalation actions
- 8 data exfiltration patterns
- 5 infrastructure destruction patterns
- 5 permissions management patterns
- 3 dangerous combination rules

### Companion Permissions Rules [DONE]
All specified rules implemented:
- Lambda → CloudWatch Logs
- VPC Lambda → EC2 ENI permissions
- KMS encrypted resources → kms:Decrypt/GenerateDataKey
- SQS consumer → full lifecycle permissions
- DynamoDB Streams → stream iteration permissions

### Python Standards [DONE]
- Type hints on ALL functions [v]
- Google-style docstrings [v]
- Dataclasses for structured data [v]
- No external dependencies (stdlib only) [v]
- pytest for unit tests [v]
- 98% code coverage (exceeds 80% target) [v]

---

## Integration with Phase 1

Phase 2 seamlessly integrates with Phase 1 modules:

1. **Database Integration**: All analyzers accept optional `Database` instance
2. **Parser Compatibility**: Works with `Policy` and `ValidationResult` objects
3. **No Breaking Changes**: All 65 Phase 1 tests still passing
4. **Unified Exports**: All classes exported via `src.sentinel.__init__.py`

---

## Verification Results

### Unit Tests
```bash
pytest tests/test_analyzer.py -v
# Result: 50/50 tests PASSED
```

### Integration Tests
```bash
pytest tests/ -v
# Result: 115/115 tests PASSED (Phase 1 + Phase 2)
```

### Coverage Report
```bash
pytest tests/ --cov=src/sentinel --cov-report=term-missing
# Result: 87% coverage, 98% for analyzer.py
```

### Verification Script
```bash
python verify_phase2.py
# Result: All Phase 2 components verified successfully
```

---

## Example: Complete Analysis Pipeline

```python
from pathlib import Path
from src.sentinel.database import Database
from src.sentinel.analyzer import (
    IntentMapper,
    RiskAnalyzer,
    CompanionPermissionDetector,
    HITLSystem
)

# Initialize components
db = Database(Path("iam_data.db"))
mapper = IntentMapper(db)
analyzer = RiskAnalyzer(db)
detector = CompanionPermissionDetector(db)
hitl = HITLSystem()

# Step 1: Map developer intent
intent_result = mapper.map_intent("deploy Lambda functions with S3 access")
print(f"Mapped to: {[level.value for level in intent_result.access_levels]}")

# Step 2: Analyze policy actions
policy_actions = [
    'lambda:*',
    's3:GetObject',
    'iam:PassRole',
    'logs:CreateLogGroup'
]

# Step 3: Risk analysis
risk_findings = analyzer.analyze_actions(policy_actions)
critical = [f for f in risk_findings if f.severity.value == "CRITICAL"]
print(f"Critical findings: {len(critical)}")

# Step 4: Check companion permissions
missing = detector.detect_missing_companions(policy_actions)
print(f"Missing companions: {len(missing)}")

# Step 5: HITL for unknown actions
if any(f.tier == "TIER_2_UNKNOWN" for f in validation_results):
    hitl.flag_tier2_action(action, assumptions)

# Step 6: Generate report
print("\nAnalysis Summary:")
print(f"  Risk Findings: {len(risk_findings)}")
print(f"  Missing Companions: {len(missing)}")
print(f"  HITL Decisions: {len(hitl.get_decision_history())}")
```

---

## Files Created/Modified

### New Files
- `src/sentinel/analyzer.py` (934 lines) - Core analyzer module
- `tests/test_analyzer.py` (621 lines) - Comprehensive test suite
- `verify_phase2.py` (454 lines) - Verification script
- `PHASE2_SUMMARY.md` - This file

### Modified Files
- `src/sentinel/__init__.py` - Added analyzer exports, version bump to 0.2.0

### Unchanged (Verified Working)
- `src/sentinel/database.py` - 100% tests passing
- `src/sentinel/parser.py` - 91% coverage, all tests passing
- `src/sentinel/inventory.py` - Phase 1 module
- All Phase 1 test files

---

## Success Criteria: ALL MET [DONE]

- [DONE] Intent mapper correctly translates natural language to access levels
- [DONE] Risk analyzer detects all dangerous patterns (wildcards, escalation, exfiltration, destruction)
- [DONE] Companion permission detector identifies missing requirements
- [DONE] HITL system properly flags Tier 2 actions
- [DONE] All 50 unit tests pass
- [DONE] 98% code coverage (exceeds 80% target)
- [DONE] Integration with Phase 1 verified
- [DONE] No external dependencies
- [DONE] Type hints and docstrings complete
- [DONE] Python standards followed

---

## Next Steps (Future Phases)

Phase 2 provides the foundation for:

**Phase 3: Policy Generation**
- Use `IntentMapper` to convert intents to actions
- Use `CompanionPermissionDetector` to add required permissions
- Generate secure, least-privilege policies

**Phase 4: Interactive CLI**
- Integrate `HITLSystem` for user confirmations
- Real-time risk analysis with `RiskAnalyzer`
- Interactive companion permission suggestions

**Phase 5: Reporting & Remediation**
- Comprehensive risk reports using `RiskFinding` objects
- Automated remediation suggestions
- Policy comparison and diff analysis

---

## Conclusion

Phase 2 successfully implements a comprehensive risk analysis engine for IAM policies. All objectives met, all tests passing, excellent code coverage, and ready for integration into the complete IAM Policy Sentinel system.

**Project Status**: Phase 1 [DONE] | Phase 2 [DONE] | Ready for Phase 3
