# Git Commit Drafts

## Purpose
This file holds draft commit messages for the IAM Policy Sentinel project.
Commits are organized by phase and feature.

---

## PHASE 0: Planning and Setup

### Commit 1: Initial project planning documents
```
feat: Add project planning and structure documentation

- Create feature.md with 10 features across 6 phases
- Create claude.md with project context and architecture
- Create progress.md for WIP tracking
- Create cartographer.md with codebase structure
- Create git_commit.md for commit message drafts
- Define 3-agent workflow (Scraper, Writer, Validator)
- Establish SQLite schemas for IAM actions and resource inventory

Files:
- feature.md (new)
- claude.md (new)
- progress.md (new)
- cartographer.md (new)
- git_commit.md (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## PHASE 1: Foundation (Database + Parser)

### Commit Template: Database schema and migrations
```
feat(database): Add SQLite schema for IAM actions and resource inventory

- Create database.py with schema definitions
- Implement migration scripts for initial setup
- Add metadata table for version tracking
- Create indexes for fast lookups

Files:
- src/sentinel/database.py (new)
- src/sentinel/__init__.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Policy parser implementation
```
feat(parser): Add IAM policy parser and validator

- Implement JSON structure validation
- Add action name syntax checking
- Add ARN format validation
- Implement three-tier action classification (Tier 1/2/3)
- Add statement structure validation

Files:
- src/sentinel/parser.py (new)
- tests/test_parser.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Resource inventory schema
```
feat(inventory): Add resource inventory SQLite schema

- Create resource_inventory.db schema
- Add resource ARN storage and indexing
- Implement resource type categorization
- Add placeholder ARN generator stubs

Files:
- src/sentinel/inventory.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## PHASE 2: Core Analysis (Risk Engine)

### Commit Template: Intent mapper
```
feat(analyzer): Add intent-to-access-level mapper

- Implement natural language intent parsing
- Map intents to AWS access levels (List, Read, Write, PermMgmt, Tagging)
- Add access level query interface to database
- Create intent mapping test cases

Files:
- src/sentinel/analyzer.py (new)
- tests/test_analyzer.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Risk detection
```
feat(analyzer): Add risk detection and dangerous permission checking

- Implement wildcard detection and scoring
- Add privilege escalation path detector
- Create dangerous permission blacklist checker
- Add missing companion permissions detector
- Implement cross-statement redundancy analyzer

Files:
- src/sentinel/analyzer.py (modified)
- tests/test_analyzer.py (modified)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: HITL system
```
feat(hitl): Add Human-in-the-Loop confirmation system

- Implement Tier 2 action detection and flagging
- Add interactive confirmation prompts
- Create user assumption validation
- Add override decision tracking

Files:
- src/sentinel/analyzer.py (modified)
- tests/test_analyzer.py (modified)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## PHASE 3: Policy Generation (Rewriter)

### Commit Template: Policy rewriter core
```
feat(rewriter): Add least-privilege policy generator

- Implement wildcard replacement logic
- Add specific ARN scoping
- Create placeholder ARN insertion for missing resources
- Implement statement reorganization
- Add descriptive Sid generation

Files:
- src/sentinel/rewriter.py (new)
- tests/test_rewriter.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Companion permissions
```
feat(rewriter): Add companion permission injection

- Implement CloudWatch Logs for Lambda
- Add VPC ec2 permissions for VPC-attached resources
- Add KMS permissions for encrypted resources
- Create condition key injection logic

Files:
- src/sentinel/rewriter.py (modified)
- tests/test_rewriter.py (modified)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Resource inventory completion
```
feat(inventory): Complete resource inventory query interface

- Implement resource ARN lookups
- Add wildcard to real ARN resolution
- Create inventory availability detection
- Add resource type filtering

Files:
- src/sentinel/inventory.py (modified)
- tests/test_inventory.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## PHASE 4: Quality Assurance (Self-Check)

### Commit Template: Self-check validator
```
feat(self-check): Add rewritten policy validation

- Implement re-validation of rewritten policies
- Add functional completeness checker
- Create Tier 2 action exclusion verifier
- Add assumption statement validator

Files:
- src/sentinel/self_check.py (new)
- tests/test_self_check.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Pipeline integration
```
feat(pipeline): Integrate four-step validation pipeline

- Connect Validate -> Analyze -> Rewrite -> Self-Check
- Add pipeline orchestration logic
- Implement error handling and rollback
- Create end-to-end integration tests

Files:
- src/sentinel/__init__.py (modified)
- tests/integration/test_pipeline.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## PHASE 5: Tooling (CLI + Refresh)

### Commit Template: CLI interface
```
feat(cli): Add command-line interface

- Implement argument parser (argparse)
- Add input policy file reader
- Create developer context prompts
- Implement output formatters (JSON, markdown, text)
- Add interactive mode support

Files:
- src/sentinel/cli.py (new)
- tests/test_cli.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Database refresh
```
feat(refresh): Add database refresh mechanisms

- Implement policy_sentry data fetcher
- Add AWS Service Authorization Reference scraper
- Create database update/merge logic
- Add version conflict resolution
- Generate changelog on updates

Files:
- src/refresh/policy_sentry.py (new)
- src/refresh/aws_docs.py (new)
- src/refresh/__init__.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## PHASE 6: Validation (Testing)

### Commit Template: Test suite
```
test: Add comprehensive test suite with 7 categories

- Create wildcard overuse test cases
- Add privilege escalation test cases
- Add missing companions test cases
- Add hallucinated actions test cases
- Add intent mismatch test cases
- Add Tier 2 unknown action test cases
- Add complex real-world test cases
- Implement regression test suite
- Add performance benchmarks

Files:
- tests/fixtures/test_policies/ (new, multiple files)
- tests/test_categories.py (new)
- tests/test_performance.py (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Commit Template: Final validation
```
test: Validate end-to-end functionality and performance

- Complete integration test coverage
- Document test results
- Add performance optimization notes
- Validate all 7 test categories pass

Files:
- tests/integration/test_e2e.py (modified)
- docs/TEST_RESULTS.md (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## Commit Guidelines

### Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- feat: New feature
- fix: Bug fix
- test: Test additions or modifications
- docs: Documentation changes
- refactor: Code refactoring
- perf: Performance improvements
- chore: Build/tooling changes

### Scopes
- database: Database schema and queries
- parser: Policy parser and validator
- analyzer: Risk analysis engine
- rewriter: Policy rewriter
- self-check: Self-check validator
- inventory: Resource inventory
- cli: Command-line interface
- refresh: Database refresh utilities
- pipeline: Full pipeline integration
- hitl: Human-in-the-Loop system

### Footer
Always include:
```
Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## Active Commits (Ready to Execute)

### Phase 0 Commit
```
feat: Add project planning and structure documentation

- Create feature.md with 10 features across 6 phases
- Create claude.md with project context and architecture
- Create progress.md for WIP tracking
- Create cartographer.md with codebase structure
- Create git_commit.md for commit message drafts
- Create IMPLEMENTATION_PLAN.md with 6-phase detailed plan
- Define 3-agent workflow (Web Scraper, Code Writer, Validator)
- Establish SQLite schemas for IAM actions and resource inventory

Files:
- feature.md (new)
- claude.md (new)
- progress.md (new)
- cartographer.md (new)
- git_commit.md (new)
- IMPLEMENTATION_PLAN.md (new)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Phase 1 Commit 1: Research
```
docs: Add IAM Policy Sentinel technical research

Agent 1 (Web Scraper) research deliverable with comprehensive
documentation of policy_sentry architecture, AWS Service Authorization
Reference format, and SQLite schema recommendations.

- 7 technical references with URLs and relevance analysis
- policy_sentry database schema documentation
- AWS Service Authorization Reference JSON format structure
- 7 sample IAM actions covering all access levels
- Normalized 10-table SQLite schema design
- Implementation roadmap and best practices

Files:
- IAM_POLICY_SENTINEL_RESEARCH.md (new, 54 pages)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Phase 1 Commit 2: Foundation Implementation
```
feat(phase1): Implement database, parser, and inventory modules

Agent 2 (Code Writer) Phase 1 implementation with complete SQLite
database interface, IAM policy parser with three-tier classification,
and resource inventory schema.

Database Module:
- SQLite interface with 10-table normalized schema
- Connection management with context managers
- Foreign key enforcement and constraint validation
- Service, action, resource type, and condition key CRUD operations
- Metadata tracking for versioning
- Read-only mode support

Parser Module:
- IAM policy JSON parser and validator
- Three-tier action classification (Tier 1/2/3)
- Wildcard support and expansion
- Suggestion engine for typo corrections
- Policy validation and summarization

Inventory Module:
- Resource inventory database schema
- Multi-tenant support (account_id, region)
- Resource ARN CRUD operations
- Query methods by service, type, account

Test Suite:
- 65 unit tests (38 database, 27 parser)
- 81% code coverage
- All tests passing

Files:
- src/sentinel/__init__.py (new)
- src/sentinel/database.py (new, 620 lines)
- src/sentinel/parser.py (new, 628 lines)
- src/sentinel/inventory.py (new, 411 lines)
- tests/test_database.py (new, 38 tests)
- tests/test_parser.py (new, 27 tests)
- data/iam_actions.db (new, empty with schema)
- data/resource_inventory.db (new, empty with schema)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Phase 1 Commit 3: Bug Fix
```
fix(database,inventory): Fix UnboundLocalError in exception handling

Agent 3 (Validator) identified critical bug where conn variable was
referenced before assignment in finally block. If sqlite3.connect()
fails before assignment, the finally block causes UnboundLocalError
instead of gracefully raising DatabaseError/InventoryError.

Fix: Initialize conn = None before try block in both modules.

Bug Details:
- Severity: CRITICAL
- Impact: Application crashes on database connection failures
- Files: database.py:142-158, inventory.py:72-88
- Root Cause: Uninitialized variable in exception handler

Validation Results:
- Initial Verdict: CONDITIONAL PASS (92/100)
- After Fix: FULL PASS (100/100)

Files Modified:
- src/sentinel/database.py (line 142)
- src/sentinel/inventory.py (line 72)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Phase 1 Commit 4: Documentation Update
```
docs: Update progress and context for Phase 1 completion

Update project documentation to reflect Phase 1 completion, bug fix,
and preparation for Phase 2.

- Mark Phase 1 complete in progress.md
- Add Phase 1 completion log to claude.md
- Document exception handling lesson learned
- Update agent coordination status
- Prepare active commits in git_commit.md

Files Modified:
- progress.md (Phase 1 marked complete)
- claude.md (thinking log added)
- git_commit.md (Phase 1 commits added)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## Notes

- All commits must be atomic (single logical change)
- Include file changes list in body
- Reference issue/feature numbers when applicable
- Keep subject line under 70 characters
- No emojis in commit messages
