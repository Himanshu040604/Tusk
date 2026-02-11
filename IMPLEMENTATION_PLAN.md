# IAM Policy Sentinel - 6-Phase Implementation Plan

## Executive Summary

Build a fully offline IAM Policy Sentinel using local SQLite databases for policy_sentry data and resource inventory. Execute through 6 phases using 3 purpose-built agents, validated against 7 categories of real-world test cases.

## Agent Architecture

### Agent 1: Web Scraper
**Mission:** Research and gather policy_sentry data structure and AWS Service Authorization Reference format
**Output:**
- policy_sentry data schema documentation
- Sample IAM actions for database seeding
- AWS Service Authorization Reference structure
- Exactly 7 distinct technical references

### Agent 2: Code Writer
**Mission:** Implement all components across all 6 phases
**Output:**
- Production-ready Python implementation
- SQLite database schemas and migrations
- Four-step pipeline (Validate -> Analyze -> Rewrite -> Self-Check)
- CLI interface and refresh utilities
- Complete test suite

### Agent 3: Validator
**Mission:** Validate implementation against requirements and test categories
**Output:**
- Code review report for each phase
- Bug identification with severity levels
- Test coverage analysis
- Integration validation
- PASS/FAIL verdict per phase

## Phase Breakdown

### PHASE 1: Foundation (Database + Parser)

**Duration:** Est. 3-5 days
**Priority:** P0 (Critical)

**Objectives:**
1. Create SQLite schemas for IAM actions and resource inventory
2. Implement database interface layer with migrations
3. Build policy JSON parser and validator
4. Implement three-tier action classification

**Deliverables:**
- src/sentinel/database.py
- src/sentinel/parser.py
- src/sentinel/inventory.py (schema only)
- data/iam_actions.db (empty, schema only)
- data/resource_inventory.db (empty, schema only)
- tests/test_parser.py
- tests/test_database.py

**Success Criteria:**
- Database schemas created and validated
- Parser correctly validates valid IAM policies
- Parser detects invalid JSON structure
- Three-tier classification correctly categorizes actions
- All Phase 1 unit tests pass

**Agent Assignments:**
- Agent 1: Provide policy_sentry schema and sample data
- Agent 2: Implement database and parser modules
- Agent 3: Validate Phase 1 implementation

---

### PHASE 2: Core Analysis (Risk Engine)

**Duration:** Est. 4-6 days
**Priority:** P0 (Critical)

**Objectives:**
1. Implement intent-to-access-level mapper
2. Build risk detection engine
3. Create dangerous permission checker
4. Implement Human-in-the-Loop system for Tier 2 actions

**Deliverables:**
- src/sentinel/analyzer.py
- tests/test_analyzer.py
- tests/fixtures/test_policies/intent_mismatch.json
- tests/fixtures/test_policies/privilege_escalation.json

**Success Criteria:**
- Intent mapper correctly translates "read-only" to List+Read
- Wildcard detection identifies * and service:* patterns
- Privilege escalation detector catches iam:PassRole combinations
- Tier 2 actions flagged for HITL confirmation
- All Phase 2 unit tests pass

**Dependencies:** Phase 1 complete

**Agent Assignments:**
- Agent 1: N/A (research complete)
- Agent 2: Implement analyzer module
- Agent 3: Validate Phase 2 implementation

---

### PHASE 3: Policy Generation (Rewriter)

**Duration:** Est. 5-7 days
**Priority:** P0 (Critical)

**Objectives:**
1. Implement least-privilege policy generator
2. Build wildcard replacement logic
3. Add companion permission injection
4. Complete resource inventory query interface

**Deliverables:**
- src/sentinel/rewriter.py
- src/sentinel/inventory.py (complete)
- tests/test_rewriter.py
- tests/test_inventory.py
- tests/fixtures/test_policies/wildcard_overuse.json
- tests/fixtures/test_policies/missing_companions.json

**Success Criteria:**
- Wildcard actions replaced with specific permissions
- Companion permissions added (Lambda logs, KMS, VPC)
- Placeholder ARNs generated when inventory unavailable
- Real ARNs used when inventory available
- Policy structure reorganized with descriptive Sids
- All Phase 3 unit tests pass

**Dependencies:** Phase 2 complete

**Agent Assignments:**
- Agent 1: N/A (research complete)
- Agent 2: Implement rewriter and complete inventory modules
- Agent 3: Validate Phase 3 implementation

---

### PHASE 4: Quality Assurance (Self-Check)

**Duration:** Est. 3-4 days
**Priority:** P0 (Critical)

**Objectives:**
1. Implement self-check validation
2. Integrate all four pipeline steps
3. Add functional completeness checking
4. Verify Tier 2 action exclusion

**Deliverables:**
- src/sentinel/self_check.py
- src/sentinel/__init__.py (pipeline orchestration)
- tests/test_self_check.py
- tests/integration/test_pipeline.py

**Success Criteria:**
- Self-check re-validates rewritten policies
- Functional completeness verified (no missing required permissions)
- Tier 2 actions excluded from final policy
- Full pipeline executes end-to-end
- All Phase 4 unit and integration tests pass

**Dependencies:** Phase 3 complete

**Agent Assignments:**
- Agent 1: N/A (research complete)
- Agent 2: Implement self-check and pipeline integration
- Agent 3: Validate Phase 4 implementation

---

### PHASE 5: Tooling (CLI + Refresh)

**Duration:** Est. 4-5 days
**Priority:** P1 (High)

**Objectives:**
1. Build command-line interface
2. Implement policy_sentry data fetcher
3. Create AWS Service Authorization scraper
4. Add database refresh/update logic

**Deliverables:**
- src/sentinel/cli.py
- src/refresh/policy_sentry.py
- src/refresh/aws_docs.py
- tests/test_cli.py

**Success Criteria:**
- CLI accepts policy file and context as input
- CLI outputs rewritten policy, risk report, change summary
- Interactive mode prompts for user confirmation
- Database refresh updates IAM actions without breaking existing data
- All Phase 5 unit tests pass

**Dependencies:** Phase 4 complete

**Agent Assignments:**
- Agent 1: Provide AWS Service Authorization scraping strategy
- Agent 2: Implement CLI and refresh utilities
- Agent 3: Validate Phase 5 implementation

---

### PHASE 6: Validation (Testing)

**Duration:** Est. 5-7 days
**Priority:** P0 (Critical)

**Objectives:**
1. Create 7 categories of test cases
2. Implement comprehensive unit tests
3. Build integration and regression tests
4. Add performance benchmarks
5. Validate against real-world scenarios

**Deliverables:**
- tests/fixtures/test_policies/01_wildcard_overuse.json
- tests/fixtures/test_policies/02_privilege_escalation.json
- tests/fixtures/test_policies/03_missing_companions.json
- tests/fixtures/test_policies/04_hallucinated_actions.json
- tests/fixtures/test_policies/05_intent_mismatch.json
- tests/fixtures/test_policies/06_tier2_unknown.json
- tests/fixtures/test_policies/07_complex_realworld.json
- tests/test_categories.py
- tests/test_performance.py
- docs/TEST_RESULTS.md

**Success Criteria:**
- All 7 test categories pass
- Test coverage > 90% for all modules
- Performance benchmarks meet targets
- Real-world test cases validate correctly
- No regressions in previously passing tests

**Dependencies:** Phase 5 complete

**Agent Assignments:**
- Agent 1: N/A (research complete)
- Agent 2: Create test suite and benchmarks
- Agent 3: Validate Phase 6 implementation and provide final project verdict

---

## Test Case Categories (7 Categories)

### Category 1: Wildcard Overuse
**Description:** Policies with *, service:*, Resource: *
**Test Cases:**
- Full wildcard (Action: *, Resource: *)
- Service wildcard (Action: s3:*, Resource: arn:aws:s3:::*)
- Resource wildcard only (Action: s3:GetObject, Resource: *)
**Expected Behavior:** Replace with specific actions and ARNs

### Category 2: Privilege Escalation
**Description:** Dangerous IAM permission combinations
**Test Cases:**
- iam:PassRole + lambda:CreateFunction
- iam:PassRole + ec2:RunInstances
- iam:CreatePolicyVersion alone
- iam:AttachRolePolicy with broad scope
**Expected Behavior:** Flag as Critical risk, require explicit justification

### Category 3: Missing Companions
**Description:** Incomplete permission sets for common scenarios
**Test Cases:**
- Lambda without CloudWatch Logs permissions
- VPC Lambda without ec2 network permissions
- KMS-encrypted S3 without kms:Decrypt
- SQS consumer without ReceiveMessage/DeleteMessage
**Expected Behavior:** Auto-add companion permissions

### Category 4: Hallucinated Actions
**Description:** Invalid or misspelled action names
**Test Cases:**
- s3:ReadObject (should be s3:GetObject)
- lambda:ExecuteFunction (should be lambda:InvokeFunction)
- cloudwatch:PutLogEvents (should be logs:PutLogEvents)
**Expected Behavior:** Flag as Tier 3 (invalid), suggest correct action

### Category 5: Intent Mismatch
**Description:** Permissions exceed stated intent
**Test Cases:**
- "read-only" intent with s3:PutObject
- "list-only" intent with dynamodb:GetItem
- "deploy" intent with iam:DeleteRole
**Expected Behavior:** Flag excess permissions, recommend removal

### Category 6: Tier 2 Unknown Actions
**Description:** Plausible but not-in-database actions
**Test Cases:**
- bedrock:InvokeModel (new service, possibly valid)
- s3express:CreateSession (new S3 feature, possibly valid)
**Expected Behavior:** Flag for HITL confirmation, exclude from rewritten policy until confirmed

### Category 7: Complex Real-World
**Description:** Multi-statement, cross-account, condition keys
**Test Cases:**
- Multi-statement policy with mixed read/write
- Cross-account S3 access with condition keys
- Step Functions with EventBridge and Lambda
**Expected Behavior:** Correctly parse, analyze, and rewrite maintaining functionality

---

## Agent Coordination Protocol

### Sequential Execution
Agents operate sequentially within each phase:
1. Agent 1 provides research/data (Phase 1 and 5 only)
2. Agent 2 implements the phase
3. Agent 3 validates before moving to next phase

### Communication Format
- Agent 1 outputs: Markdown documentation with code samples
- Agent 2 outputs: Complete Python modules with tests
- Agent 3 outputs: PASS/FAIL verdict with detailed findings

### Phase Gate Criteria
Each phase must receive PASS from Agent 3 before proceeding to next phase.

**PASS Criteria:**
- All unit tests pass
- Code review identifies no Critical or High severity bugs
- Implementation matches phase objectives
- Test coverage meets minimum threshold (80%)

**FAIL Criteria:**
- Critical or High severity bugs found
- Missing required functionality
- Test failures
- Code quality issues (no type hints, missing docstrings)

**Remediation:**
If Agent 3 returns FAIL, Agent 2 fixes issues and Agent 3 re-validates.

---

## Technical Specifications

### Database Schemas

**iam_actions.db:**
```sql
CREATE TABLE services (
    service_prefix TEXT PRIMARY KEY,
    service_name TEXT NOT NULL
);

CREATE TABLE actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_prefix TEXT NOT NULL,
    action_name TEXT NOT NULL,
    access_level TEXT NOT NULL,
    resource_types TEXT,
    condition_keys TEXT,
    UNIQUE(service_prefix, action_name),
    FOREIGN KEY (service_prefix) REFERENCES services(service_prefix)
);

CREATE TABLE resource_types (
    resource_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_prefix TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    arn_pattern TEXT NOT NULL,
    FOREIGN KEY (service_prefix) REFERENCES services(service_prefix)
);

CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX idx_action_lookup ON actions(service_prefix, action_name);
CREATE INDEX idx_access_level ON actions(access_level);
```

**resource_inventory.db:**
```sql
CREATE TABLE resources (
    resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_prefix TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_arn TEXT UNIQUE NOT NULL,
    resource_name TEXT,
    region TEXT,
    account_id TEXT,
    metadata TEXT
);

CREATE INDEX idx_service ON resources(service_prefix);
CREATE INDEX idx_type ON resources(resource_type);
CREATE INDEX idx_arn ON resources(resource_arn);
```

### Python Module Structure

**All modules must:**
- Use Python 3.9+ type hints
- Include Google-style docstrings
- Implement dataclasses for structured data
- Raise specific exceptions with context
- Include unit tests with 80%+ coverage

### Access Levels
- List: Enumerate resources (s3:ListBucket, ec2:DescribeInstances)
- Read: Read resource data (s3:GetObject, dynamodb:GetItem)
- Write: Create/modify/delete resources (s3:PutObject, ec2:RunInstances)
- Permissions Management: Modify policies (s3:PutBucketPolicy, iam:AttachRolePolicy)
- Tagging: Manage tags (s3:PutObjectTagging, ec2:CreateTags)

---

## Risk Management

### Technical Risks

**Risk 1:** policy_sentry data format changes
**Mitigation:** Version database schema, implement migration scripts, document assumptions
**Owner:** Agent 2

**Risk 2:** SQLite performance with 10,000+ actions
**Mitigation:** Proper indexing, query optimization, benchmark Phase 6
**Owner:** Agent 2

**Risk 3:** Complex policy edge cases
**Mitigation:** Comprehensive test suite (7 categories), real-world scenarios
**Owner:** Agent 3

**Risk 4:** Agent coordination overhead
**Mitigation:** Clear phase gates, sequential execution, PASS/FAIL criteria
**Owner:** Project orchestrator (Claude)

### Schedule Risks

**Risk 1:** Phase delays
**Mitigation:** Time-box phases, cut low-priority features if needed
**Owner:** Project orchestrator

**Risk 2:** Agent 3 finds Critical bugs late in phase
**Mitigation:** Incremental validation, early code reviews
**Owner:** Agent 3

---

## Success Metrics

### Phase Completion Metrics
- All unit tests pass
- Code coverage > 80%
- Agent 3 PASS verdict
- No Critical or High severity bugs

### Project Completion Metrics
- All 6 phases complete
- All 7 test categories pass
- End-to-end integration validated
- Performance benchmarks met
- Documentation complete

### Performance Targets
- Policy validation: < 100ms for typical policy
- Risk analysis: < 500ms for typical policy
- Policy rewrite: < 1s for typical policy
- Database query: < 10ms per action lookup

---

## Timeline

### Phase 0: Planning (COMPLETE)
- Duration: 1 day
- Status: COMPLETE

### Phase 1: Foundation
- Duration: 3-5 days
- Start: After Agent 1 provides data schema

### Phase 2: Core Analysis
- Duration: 4-6 days
- Start: After Phase 1 PASS

### Phase 3: Policy Generation
- Duration: 5-7 days
- Start: After Phase 2 PASS

### Phase 4: Quality Assurance
- Duration: 3-4 days
- Start: After Phase 3 PASS

### Phase 5: Tooling
- Duration: 4-5 days
- Start: After Phase 4 PASS

### Phase 6: Validation
- Duration: 5-7 days
- Start: After Phase 5 PASS

**Total Estimated Duration:** 25-35 days

---

## Next Steps

1. Update progress.md to mark Phase 0 complete
2. Spawn Agent 1 (Web Scraper) for policy_sentry research
3. Wait for Agent 1 completion
4. Spawn Agent 2 (Code Writer) for Phase 1 implementation
5. Wait for Agent 2 completion
6. Spawn Agent 3 (Validator) for Phase 1 validation
7. If PASS: Proceed to Phase 2
8. If FAIL: Agent 2 fixes issues, Agent 3 re-validates

---

## Appendix: Agent Prompts

### Agent 1 Prompt Template
```
You are Agent 1 (Web Scraper) in a 3-agent workflow for the IAM Policy Sentinel project.

Mission: Research and document policy_sentry data structure and AWS Service Authorization Reference format.

Requirements:
1. Search for policy_sentry Python library documentation
2. Identify database schema and data format
3. Extract sample IAM actions for testing
4. Document AWS Service Authorization Reference structure
5. Provide exactly 7 distinct technical references

Output Format:
- policy_sentry schema documentation
- Sample IAM actions (JSON format)
- AWS Service Auth Reference structure
- 7 technical references with URLs

Begin research now.
```

### Agent 2 Prompt Template (Phase 1)
```
You are Agent 2 (Code Writer) in a 3-agent workflow for the IAM Policy Sentinel project.

Mission: Implement Phase 1 (Foundation) - Database + Parser

Context from Agent 1: [insert Agent 1 output]

Requirements:
1. Create SQLite schemas for iam_actions.db and resource_inventory.db
2. Implement database.py with query interface
3. Implement parser.py with JSON validation and three-tier classification
4. Implement inventory.py schema (storage only)
5. Write unit tests for all components
6. Use Python type hints and Google-style docstrings

Deliverables:
- src/sentinel/database.py
- src/sentinel/parser.py
- src/sentinel/inventory.py
- tests/test_database.py
- tests/test_parser.py

Success Criteria:
- All tests pass
- Type hints on all functions
- 80%+ code coverage

Begin implementation now.
```

### Agent 3 Prompt Template (Phase 1)
```
You are Agent 3 (Validator) in a 3-agent workflow for the IAM Policy Sentinel project.

Mission: Validate Phase 1 implementation against requirements.

Context: Agent 2 has implemented Phase 1 (Foundation) - Database + Parser

Validation Tasks:
1. Review code for bugs and logic errors
2. Verify database schema correctness
3. Run all unit tests and check coverage
4. Validate parser handles edge cases
5. Check type hints and docstrings

Output Format:
PASS or FAIL with:
- List of bugs found (severity: Critical/High/Medium/Low)
- Test coverage report
- Code quality assessment
- Recommendations for improvements

Begin validation now.
```

---

## Document Version

Version: 1.0
Created: 2026-02-12
Last Updated: 2026-02-12
