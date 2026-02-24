# IAM Policy Sentinel - Feature Breakdown

## Project Overview
Fully offline IAM Policy Sentinel for AWS security validation and least-privilege enforcement.

## Core Features

### FEATURE 1: Local IAM Action Database (SQLite)
**Status:** COMPLETE (Phase 1)
**Dependencies:** None
**Tasks:**
1. Design SQLite schema for IAM actions database
2. Create migration scripts for initial schema
3. Implement policy_sentry data import utility
4. Build query interface for action lookups
5. Add database versioning and metadata tracking

### FEATURE 2: Policy Parser and Validator
**Status:** COMPLETE (Phase 1)
**Dependencies:** FEATURE 1
**Tasks:**
1. JSON policy structure validator
2. Action name syntax validation
3. ARN format validation
4. Three-tier action classification (Tier 1/2/3)
5. Statement structure validation

### FEATURE 3: Risk Analysis Engine
**Status:** COMPLETE (Phase 2)
**Dependencies:** FEATURE 1, FEATURE 2
**Tasks:**
1. Intent-to-access-level mapper (List, Read, Write, PermMgmt, Tagging)
2. Wildcard detection and scoring
3. Privilege escalation path detector
4. Dangerous permission blacklist checker
5. Missing companion permissions detector
6. Cross-statement redundancy analyzer

### FEATURE 4: Policy Rewriter
**Status:** COMPLETE (Phase 3)
**Dependencies:** FEATURE 1, FEATURE 2, FEATURE 3
**Tasks:**
1. Least-privilege policy generator
2. Wildcard replacement logic (real ARNs or placeholders)
3. Condition key injection
4. Companion permission addition
5. Statement reorganization and cleanup

### FEATURE 5: Resource Inventory System
**Status:** COMPLETE (Phase 1 schema, Phase 3 full)
**Dependencies:** FEATURE 1
**Tasks:**
1. SQLite schema for resource inventory
2. Resource ARN storage and indexing
3. Resource type categorization
4. Inventory query interface
5. Placeholder ARN generator for missing resources

### FEATURE 6: Human-in-the-Loop (HITL) System
**Status:** COMPLETE (Phase 2)
**Dependencies:** FEATURE 2, FEATURE 3
**Tasks:**
1. Tier 2 action detection and flagging
2. Interactive confirmation prompt system
3. User assumption validation
4. Override decision tracking

### FEATURE 7: Database Refresh Mechanism
**Status:** Pending
**Dependencies:** FEATURE 1
**Tasks:**
1. policy_sentry data fetcher
2. AWS Service Authorization Reference scraper
3. Database update/merge logic
4. Version conflict resolution
5. Changelog generation

### FEATURE 8: Self-Check Validation
**Status:** Pending
**Dependencies:** FEATURE 2, FEATURE 4
**Tasks:**
1. Rewritten policy re-validation
2. Functional completeness checker
3. Tier 2 action exclusion verification
4. Assumption statement validator

### FEATURE 9: CLI Interface
**Status:** Pending
**Dependencies:** FEATURE 2, FEATURE 3, FEATURE 4, FEATURE 8
**Tasks:**
1. Command-line argument parser
2. Input policy file reader
3. Developer context prompt
4. Output formatter (JSON, markdown, text)
5. Interactive mode support

### FEATURE 10: Test Suite
**Status:** Pending
**Dependencies:** All features
**Tasks:**
1. Test case database (7 categories)
2. Unit tests for each component
3. Integration tests for full pipeline
4. Regression test suite
5. Performance benchmarks

## Feature Dependency Graph

```
FEATURE 1 (Database)
    |
    +-- FEATURE 2 (Parser) -- FEATURE 8 (Self-Check)
    |       |                      |
    |       +-- FEATURE 3 (Risk) --+
    |       |       |               |
    |       |       +-- FEATURE 4 (Rewriter)
    |       |                       |
    |       +-- FEATURE 6 (HITL)   |
    |                               |
    +-- FEATURE 5 (Inventory) -----+
    |                               |
    +-- FEATURE 7 (Refresh)        |
                                    |
                        FEATURE 9 (CLI)
                                    |
                        FEATURE 10 (Tests)
```

## 6-Phase Implementation Plan

### PHASE 1: Foundation (Database + Parser)
- FEATURE 1: Local IAM Action Database
- FEATURE 2: Policy Parser and Validator
- FEATURE 5: Resource Inventory System (schema only)

### PHASE 2: Core Analysis (Risk Engine)
- FEATURE 3: Risk Analysis Engine
- FEATURE 6: Human-in-the-Loop System

### PHASE 3: Policy Generation (Rewriter)
- FEATURE 4: Policy Rewriter
- FEATURE 5: Resource Inventory System (complete)

### PHASE 4: Quality Assurance (Self-Check)
- FEATURE 8: Self-Check Validation
- Integration of all pipeline steps

### PHASE 5: Tooling (CLI + Refresh)
- FEATURE 9: CLI Interface
- FEATURE 7: Database Refresh Mechanism

### PHASE 6: Validation (Testing)
- FEATURE 10: Test Suite (7 categories)
- End-to-end validation
- Performance optimization

## Test Case Categories

1. **Wildcard Overuse**: Policies with *, service:*, Resource: *
2. **Privilege Escalation**: iam:PassRole, iam:AttachRolePolicy combinations
3. **Missing Companions**: Lambda without logs, VPC without ec2, KMS scenarios
4. **Hallucinated Actions**: Fake action names, typos, wrong verbs
5. **Intent Mismatch**: "read-only" intent with Write actions
6. **Tier 2 Unknown**: Plausible but not-in-database actions
7. **Complex Real-World**: Multi-statement, cross-account, condition keys

## Stable Dependencies

- Python 3.9+
- SQLite3 (built-in)
- tiktoken (for token counting, optional)
- No AWS SDK (boto3) - fully offline
- No external APIs

## Non-Goals (Explicitly Excluded)

- Live AWS API calls
- Real-time resource discovery
- Cross-account IAM analysis (basic support only)
- Service Control Policies (SCP)
- Permission boundaries (basic support only)
- GUI/Web interface (CLI only)
