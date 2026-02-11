# Claude Code Skills Reference

This document lists all available skills in Claude Code. Claude will read this file and automatically select the appropriate skill based on your task requirements.

---

## 📋 TABLE OF CONTENTS

1. [Core Workflow Skills](#core-workflow-skills) - Essential development workflows
2. [Agent Orchestration](#agent-orchestration) - Multi-agent coordination
3. [Backend Development](#backend-development) - Server-side architecture and APIs
4. [CI/CD & DevOps](#cicd--devops) - Deployment and infrastructure
5. [Database Management](#database-management) - Data persistence and optimization
6. [Code Quality](#code-quality) - Testing, debugging, and review
7. [Documentation](#documentation) - Technical writing and guides
8. [Project Management](#project-management) - Conductor framework for structured development
9. [Configuration](#configuration) - Environment and settings management

---

## CORE WORKFLOW SKILLS

### superpowers:using-superpowers ⭐ **START HERE**
**When to use:** At the beginning of ANY conversation
**Purpose:** Establishes how to find and use skills; requires Skill tool invocation before ANY response including clarifying questions
**Priority:** MANDATORY - Use first before any other skill

### superpowers:brainstorming
**When to use:** BEFORE any creative work - creating features, building components, adding functionality, or modifying behavior
**Purpose:** Explores user intent, requirements, and design before implementation
**Priority:** HIGH - Use proactively for creative tasks

### superpowers:writing-plans
**When to use:** When you have a spec or requirements for a multi-step task, BEFORE touching code
**Purpose:** Creates structured implementation plans
**Priority:** HIGH - Plan before coding

### superpowers:executing-plans
**When to use:** When you have a written implementation plan to execute in a separate session with review checkpoints
**Purpose:** Executes pre-written plans with validation gates
**Priority:** MEDIUM

### superpowers:subagent-driven-development
**When to use:** When executing implementation plans with independent tasks in the current session
**Purpose:** Parallelizes work using multiple subagents
**Priority:** MEDIUM

### superpowers:test-driven-development
**When to use:** When implementing any feature or bugfix, BEFORE writing implementation code
**Purpose:** Write tests first, then implement to pass them
**Priority:** HIGH - Use for all feature development

### superpowers:systematic-debugging
**When to use:** When encountering any bug, test failure, or unexpected behavior, BEFORE proposing fixes
**Purpose:** Structured debugging methodology
**Priority:** HIGH - Use proactively for all bugs

### superpowers:verification-before-completion
**When to use:** Before claiming work is complete, fixed, or passing; before committing or creating PRs
**Purpose:** Requires running verification commands and confirming output; evidence before assertions
**Priority:** CRITICAL - Always verify before completion

### superpowers:requesting-code-review
**When to use:** When completing tasks, implementing major features, or before merging
**Purpose:** Verify work meets requirements and quality standards
**Priority:** HIGH

### superpowers:receiving-code-review
**When to use:** When receiving code review feedback, before implementing suggestions
**Purpose:** Ensures technical rigor and verification, not blind implementation
**Priority:** HIGH

### superpowers:finishing-a-development-branch
**When to use:** When implementation is complete, all tests pass, and you need to decide how to integrate
**Purpose:** Guides completion by presenting structured options for merge, PR, or cleanup
**Priority:** MEDIUM

### superpowers:using-git-worktrees
**When to use:** When starting feature work that needs isolation from current workspace
**Purpose:** Creates isolated git worktrees with smart directory selection
**Priority:** MEDIUM

### superpowers:writing-skills
**When to use:** When creating new skills, editing existing skills, or verifying skills work
**Purpose:** Skill development and validation
**Priority:** LOW - Specialized use case

---

## AGENT ORCHESTRATION

### codex-orchestrator ⭐ **DEFAULT FOR EXECUTION**
**When to use:** DEFAULT PIPELINE for ALL tasks requiring execution - code, file modifications, codebase research, multi-step work
**Purpose:** You are the orchestrator; Codex agents are hyper-focused implementation specialists
**Priority:** CRITICAL - This is NOT optional for execution work
**Note:** Only skip if user explicitly asks you to do something yourself

### superpowers:dispatching-parallel-agents
**When to use:** When facing 2+ independent tasks without shared state or sequential dependencies
**Purpose:** Parallel execution of independent tasks
**Priority:** HIGH - Use for parallelizable work

### agent-teams:team-spawn
**When to use:** Need to create a multi-agent team for complex work
**Purpose:** Spawn agent teams using presets (review, debug, feature, fullstack, research, security, migration)
**Presets:** review, debug, feature, fullstack, research, security, migration
**Priority:** MEDIUM

### agent-teams:team-status
**When to use:** Need to check progress of an active agent team
**Purpose:** Display team members, task status, and progress
**Priority:** LOW - Monitoring

### agent-teams:team-delegate
**When to use:** Need to manage team workload and rebalance assignments
**Purpose:** Task delegation dashboard
**Priority:** LOW - Team management

### agent-teams:team-shutdown
**When to use:** Need to gracefully stop an agent team
**Purpose:** Collect final results and clean up resources
**Priority:** LOW - Cleanup

### agent-teams:team-debug
**When to use:** Debug issues using competing hypotheses
**Purpose:** Parallel investigation by multiple agents
**Priority:** MEDIUM

### agent-teams:team-feature
**When to use:** Develop features in parallel with multiple agents
**Purpose:** File ownership boundaries and dependency management
**Priority:** MEDIUM

### agent-teams:team-review
**When to use:** Launch multi-reviewer parallel code review
**Purpose:** Specialized review dimensions (security, performance, architecture, testing, accessibility)
**Priority:** MEDIUM

### Agent Team Pattern Skills
- **agent-teams:multi-reviewer-patterns** - Coordinate parallel code reviews
- **agent-teams:parallel-debugging** - Debug with competing hypotheses
- **agent-teams:parallel-feature-development** - Coordinate parallel feature work
- **agent-teams:task-coordination-strategies** - Decompose and coordinate complex tasks
- **agent-teams:team-communication-protocols** - Structured messaging for teams
- **agent-teams:team-composition-patterns** - Design optimal team compositions

---

## BACKEND DEVELOPMENT

### backend-development:backend-architect ⭐ **PROACTIVE**
**When to use:** Creating new backend services or APIs
**Purpose:** Scalable API design, microservices architecture, distributed systems
**Expertise:** REST/GraphQL/gRPC, event-driven architectures, service mesh patterns
**Priority:** HIGH - Use proactively

### backend-development:feature-development
**When to use:** Orchestrate end-to-end feature development
**Purpose:** From requirements to deployment
**Priority:** MEDIUM

### backend-development:api-design-principles
**When to use:** Designing new APIs, reviewing API specs, establishing standards
**Purpose:** REST and GraphQL API design best practices
**Priority:** HIGH

### backend-development:architecture-patterns
**When to use:** Architecting complex backend systems or refactoring for maintainability
**Purpose:** Clean Architecture, Hexagonal Architecture, Domain-Driven Design
**Priority:** HIGH

### backend-development:microservices-patterns
**When to use:** Building distributed systems, decomposing monoliths
**Purpose:** Service boundaries, event-driven communication, resilience patterns
**Priority:** MEDIUM

### backend-development:event-sourcing-architect ⭐ **PROACTIVE**
**When to use:** Event-sourced systems, audit trail requirements, temporal queries
**Purpose:** Event sourcing, CQRS, event-driven architecture patterns
**Priority:** MEDIUM

### backend-development:cqrs-implementation
**When to use:** Separating read/write models, optimizing query performance
**Purpose:** Command Query Responsibility Segregation
**Priority:** MEDIUM

### backend-development:event-store-design
**When to use:** Building event sourcing infrastructure
**Purpose:** Event store design and implementation
**Priority:** LOW - Specialized

### backend-development:projection-patterns
**When to use:** Implementing CQRS read sides, materialized views
**Purpose:** Build read models from event streams
**Priority:** LOW - Specialized

### backend-development:saga-orchestration
**When to use:** Coordinating multi-step business processes, distributed transactions
**Purpose:** Saga patterns for long-running workflows
**Priority:** MEDIUM

### backend-development:temporal-python-pro ⭐ **PROACTIVE**
**When to use:** Workflow design, microservice orchestration, long-running processes
**Purpose:** Master Temporal workflow orchestration with Python SDK
**Priority:** MEDIUM

### backend-development:temporal-python-testing
**When to use:** Implementing Temporal workflow tests
**Purpose:** Test workflows with pytest, time-skipping, mocking
**Priority:** LOW - Testing

### backend-development:workflow-orchestration-patterns
**When to use:** Building long-running processes, distributed transactions
**Purpose:** Design durable workflows with Temporal
**Priority:** MEDIUM

### backend-development:graphql-architect ⭐ **PROACTIVE**
**When to use:** GraphQL architecture or performance optimization
**Purpose:** Modern GraphQL with federation, performance, security
**Priority:** MEDIUM

### backend-development:security-auditor
**When to use:** Security review during feature development
**Purpose:** Review for OWASP Top 10, auth flaws, compliance issues
**Priority:** HIGH

### backend-development:performance-engineer
**When to use:** Performance review during feature development
**Purpose:** Profile and optimize response times, memory, query efficiency
**Priority:** MEDIUM

### backend-development:test-automator
**When to use:** Test creation during feature development
**Purpose:** Create unit, integration, and E2E tests; TDD/BDD workflows
**Priority:** HIGH

### backend-development:tdd-orchestrator ⭐ **PROACTIVE**
**When to use:** TDD implementation and governance
**Purpose:** Master TDD orchestrator with red-green-refactor discipline
**Priority:** HIGH

### backend-api-security:backend-security-coder ⭐ **PROACTIVE**
**When to use:** Backend security implementations or security code reviews
**Purpose:** Input validation, authentication, API security
**Priority:** HIGH

---

## CI/CD & DEVOPS

### cicd-automation:cloud-architect ⭐ **PROACTIVE**
**When to use:** Cloud architecture, cost optimization, migration planning, multi-cloud strategies
**Purpose:** AWS/Azure/GCP multi-cloud infrastructure, IaC, FinOps
**Expertise:** Terraform/OpenTofu/CDK, serverless, microservices, security
**Priority:** HIGH

### cicd-automation:kubernetes-architect ⭐ **PROACTIVE**
**When to use:** K8s architecture, GitOps implementation, cloud-native platform design
**Purpose:** Cloud-native infrastructure, GitOps (ArgoCD/Flux), container orchestration
**Expertise:** EKS/AKS/GKE, service mesh (Istio/Linkerd), progressive delivery
**Priority:** HIGH

### cicd-automation:terraform-specialist ⭐ **PROACTIVE**
**When to use:** Advanced IaC, state management, infrastructure automation
**Purpose:** Terraform/OpenTofu advanced automation
**Expertise:** Module design, multi-cloud, GitOps, policy as code
**Priority:** HIGH

### cicd-automation:devops-troubleshooter ⭐ **PROACTIVE**
**When to use:** Debugging, incident response, system troubleshooting
**Purpose:** Rapid incident response, advanced debugging, observability
**Expertise:** Log analysis, distributed tracing, K8s debugging, performance optimization
**Priority:** HIGH

### cicd-automation:deployment-engineer
**When to use:** General CI/CD automation tasks
**Purpose:** Deployment automation
**Priority:** MEDIUM

### cicd-automation:deployment-pipeline-design
**When to use:** Architecting deployment workflows, continuous delivery, GitOps
**Purpose:** Multi-stage CI/CD pipelines with approval gates, security checks
**Priority:** MEDIUM

### cicd-automation:github-actions-templates
**When to use:** Setting up CI/CD with GitHub Actions
**Purpose:** Production-ready GitHub Actions workflows
**Priority:** MEDIUM

### cicd-automation:gitlab-ci-patterns
**When to use:** Implementing GitLab CI/CD
**Purpose:** GitLab CI/CD pipelines with caching and distributed runners
**Priority:** MEDIUM

### cicd-automation:secrets-management
**When to use:** Handling sensitive credentials, rotating secrets
**Purpose:** Secure secrets management (Vault, AWS Secrets Manager)
**Priority:** HIGH

---

## DATABASE MANAGEMENT

### database-design:database-architect ⭐ **PROACTIVE**
**When to use:** Database architecture, technology selection, data modeling decisions
**Purpose:** Data layer design from scratch, schema modeling, scalable architectures
**Expertise:** SQL/NoSQL/TimeSeries selection, normalization, migration planning
**Priority:** HIGH

### database-design:sql-pro ⭐ **PROACTIVE**
**When to use:** Database optimization or complex analysis
**Purpose:** Modern SQL with cloud-native databases, OLTP/OLAP optimization
**Priority:** MEDIUM

### database-design:postgresql
**When to use:** Designing PostgreSQL-specific schemas
**Purpose:** PostgreSQL best practices, data types, indexing, performance
**Priority:** MEDIUM

### database-migrations:database-admin
**When to use:** Database architecture, operations, reliability engineering
**Purpose:** Modern cloud databases, automation, reliability
**Expertise:** AWS/Azure/GCP database services, IaC, high availability
**Priority:** MEDIUM

### database-migrations:database-optimizer ⭐ **PROACTIVE**
**When to use:** Database optimization, performance issues, scalability challenges
**Purpose:** Performance tuning, query optimization, scalable architectures
**Expertise:** Advanced indexing, N+1 resolution, caching, partitioning
**Priority:** HIGH

### database-migrations:sql-migrations
**When to use:** Database schema migrations
**Purpose:** Zero-downtime SQL migrations for PostgreSQL, MySQL, SQL Server
**Priority:** MEDIUM

### database-migrations:migration-observability
**When to use:** Migration monitoring and observability infrastructure
**Purpose:** CDC, monitoring, observability for migrations
**Priority:** LOW

---

## CODE QUALITY

### debugging-toolkit:debugger ⭐ **PROACTIVE**
**When to use:** Any errors, test failures, unexpected behavior
**Purpose:** Debugging specialist
**Priority:** HIGH - Use proactively

### error-debugging:debugger
**When to use:** Debugging issues, analyzing logs, investigating errors
**Purpose:** Advanced debugging specialist
**Priority:** HIGH

### error-debugging:error-detective ⭐ **PROACTIVE**
**When to use:** Searching logs, correlating errors, root cause analysis
**Purpose:** Search logs for error patterns, stack traces, anomalies
**Priority:** HIGH

### code-refactoring:code-reviewer ⭐ **PROACTIVE**
**When to use:** Code quality assurance
**Purpose:** AI-powered code analysis, security, performance, reliability
**Priority:** HIGH

### code-refactoring:legacy-modernizer ⭐ **PROACTIVE**
**When to use:** Legacy system updates, framework migrations, technical debt
**Purpose:** Refactor legacy code, migrate frameworks, gradual modernization
**Priority:** MEDIUM

### code-review:code-review
**When to use:** Code review a pull request
**Purpose:** Comprehensive PR review
**Priority:** HIGH

### superpowers:code-reviewer ⭐
**When to use:** After major project step completion, before merging
**Purpose:** Review implementation against plan and coding standards
**Priority:** HIGH

### code-simplifier:code-simplifier
**When to use:** Need to simplify and refine code
**Purpose:** Improve clarity, consistency, maintainability while preserving functionality
**Priority:** MEDIUM

### debugging-toolkit:dx-optimizer ⭐ **PROACTIVE**
**When to use:** Setting up new projects, after team feedback, when friction noticed
**Purpose:** Improve tooling, setup, workflows (Developer Experience)
**Priority:** MEDIUM

### python-best-practices ⭐ **MUST USE FOR PYTHON**
**When to use:** Reading or writing Python files
**Purpose:** Type-first development with dataclasses, discriminated unions, NewType, Protocol
**Priority:** CRITICAL - Must use for all Python work

### python-testing-patterns
**When to use:** Writing Python tests, setting up test suites
**Purpose:** pytest, fixtures, mocking, TDD
**Priority:** HIGH

### error-handling-patterns
**When to use:** Implementing error handling, designing APIs, improving reliability
**Purpose:** Exceptions, Result types, error propagation, graceful degradation
**Priority:** MEDIUM

---

## DOCUMENTATION

### code-documentation:docs-architect ⭐ **PROACTIVE**
**When to use:** System documentation, architecture guides, technical deep-dives
**Purpose:** Comprehensive technical documentation from codebases
**Output:** Long-form manuals, architecture analysis
**Priority:** MEDIUM

### code-documentation:tutorial-engineer ⭐ **PROACTIVE**
**When to use:** Onboarding guides, feature tutorials, concept explanations
**Purpose:** Step-by-step tutorials and educational content
**Output:** Progressive learning experiences
**Priority:** MEDIUM

### code-documentation:code-reviewer ⭐ **PROACTIVE**
**When to use:** Code quality assurance before documentation
**Purpose:** AI-powered code analysis for docs
**Priority:** MEDIUM

### cartographer ⭐
**When to use:** "map this codebase", "cartographer", "/cartographer", "create codebase map", "document the architecture"
**Purpose:** Maps and documents codebases; creates docs/CODEBASE_MAP.md
**Output:** Architecture, file purposes, dependencies, navigation guides
**Priority:** HIGH - Onboarding to new projects

---

## PROJECT MANAGEMENT (Conductor Framework)

### conductor:setup
**When to use:** Initialize project with Conductor methodology
**Purpose:** Create product definition, tech stack, workflow, style guides
**Priority:** HIGH - Project initialization

### conductor:new-track
**When to use:** Create new feature, bug fix, or refactor work unit
**Purpose:** Create track with specification and phased implementation plan
**Priority:** HIGH

### conductor:implement
**When to use:** Execute tasks from a track's implementation plan
**Purpose:** Follow TDD workflow for track execution
**Priority:** HIGH

### conductor:status
**When to use:** Check project status
**Purpose:** Display active tracks and next actions
**Priority:** LOW - Monitoring

### conductor:manage
**When to use:** Archive, restore, delete, rename, or cleanup tracks
**Purpose:** Track lifecycle management
**Priority:** LOW - Maintenance

### conductor:revert
**When to use:** Need to undo work by logical unit
**Purpose:** Git-aware undo by track, phase, or task
**Priority:** MEDIUM

### conductor:context-driven-development
**When to use:** Working with Conductor methodology and context artifacts
**Purpose:** Understand product.md, tech-stack.md, workflow.md relationship
**Priority:** LOW - Reference

### conductor:track-management
**When to use:** Managing Conductor tracks
**Purpose:** Understand spec.md, plan.md, track lifecycle
**Priority:** LOW - Reference

### conductor:workflow-patterns
**When to use:** Implementing tasks with Conductor TDD workflow
**Purpose:** Phase checkpoints, git commits, verification protocol
**Priority:** LOW - Reference

### conductor:conductor-validator
**When to use:** After setup, when diagnosing issues, before implementation
**Purpose:** Validate Conductor artifacts for completeness
**Priority:** MEDIUM

---

## CONFIGURATION

### keybindings-help
**When to use:** User wants to customize keyboard shortcuts, rebind keys, add chord bindings
**Examples:** "rebind ctrl+s", "add a chord shortcut", "change the submit key"
**Priority:** LOW - Configuration

### claude-md-management:revise-claude-md
**When to use:** Update CLAUDE.md with learnings from session
**Purpose:** Maintain project memory and context
**Priority:** LOW - Maintenance

### claude-md-management:claude-md-improver
**When to use:** User asks to check, audit, update, improve, or fix CLAUDE.md files
**Purpose:** Audit and improve CLAUDE.md files; output quality report; make updates
**Priority:** MEDIUM

### context-management:context-manager ⭐ **PROACTIVE**
**When to use:** Complex AI orchestration, managing context across workflows
**Purpose:** Dynamic context management, vector DBs, knowledge graphs, memory systems
**Priority:** MEDIUM

---

## SPECIALIZED SKILLS

### feature-dev:feature-dev
**When to use:** Guided feature development
**Purpose:** Codebase understanding and architecture focus
**Priority:** MEDIUM

### feature-dev:code-architect
**When to use:** Design feature architectures
**Purpose:** Analyze patterns, provide implementation blueprints
**Priority:** MEDIUM

### feature-dev:code-explorer
**When to use:** Deep codebase analysis
**Purpose:** Trace execution paths, map architecture, understand patterns
**Priority:** MEDIUM

### feature-dev:code-reviewer
**When to use:** Code review with confidence-based filtering
**Purpose:** Find bugs, logic errors, security vulnerabilities
**Priority:** HIGH

### agent-sdk-dev:new-sdk-app
**When to use:** Create new Claude Agent SDK application
**Purpose:** Setup SDK app
**Priority:** LOW - Specialized

### agent-sdk-dev:agent-sdk-verifier-py
**When to use:** After creating/modifying Python Agent SDK app
**Purpose:** Verify Python SDK app follows best practices
**Priority:** LOW - Specialized

### agent-sdk-dev:agent-sdk-verifier-ts
**When to use:** After creating/modifying TypeScript Agent SDK app
**Purpose:** Verify TypeScript SDK app follows best practices
**Priority:** LOW - Specialized

### architecture-patterns
**When to use:** Architecting complex backend systems
**Purpose:** Clean Architecture, Hexagonal Architecture, Domain-Driven Design
**Priority:** HIGH

### monorepo-management
**When to use:** Setting up monorepos, optimizing builds, managing shared dependencies
**Purpose:** Turborepo, Nx, pnpm workspaces
**Priority:** MEDIUM

### prompt-engineering-patterns
**When to use:** Optimizing prompts, improving LLM outputs, designing production templates
**Purpose:** Advanced prompt engineering for production
**Priority:** MEDIUM

### debugging-strategies
**When to use:** Investigating bugs, performance issues, unexpected behavior
**Purpose:** Systematic debugging, profiling, root cause analysis
**Priority:** HIGH

### git-advanced-workflows
**When to use:** Managing complex Git histories, collaborating on branches, troubleshooting repo
**Purpose:** Rebasing, cherry-picking, bisect, worktrees, reflog
**Priority:** MEDIUM

---

## SKILL SELECTION GUIDELINES

### Priority Levels
- **CRITICAL**: MUST use (mandatory)
- **HIGH**: Should use proactively
- **MEDIUM**: Use when appropriate
- **LOW**: Use for specialized cases

### Proactive Skills (⭐)
These skills should be used WITHOUT user explicitly asking:
- All skills marked **PROACTIVE** in descriptions
- codex-orchestrator (default for execution)
- python-best-practices (for all Python work)
- superpowers:using-superpowers (start of conversation)

### Selection Process
1. **Read this file** at the start of each task
2. **Identify task category** (development, debugging, documentation, etc.)
3. **Match task to skill specifications**
4. **Select most specific skill** that matches requirements
5. **Use Skill tool** to invoke before proceeding

### Multiple Skills
- Some tasks may require **multiple skills in sequence**
- Example: brainstorming → writing-plans → codex-orchestrator → verification-before-completion
- Always follow the logical workflow order

---

## QUICK REFERENCE

### I need to...
- **Start a conversation** → superpowers:using-superpowers
- **Create a new feature** → superpowers:brainstorming → superpowers:writing-plans
- **Execute a plan** → codex-orchestrator or superpowers:executing-plans
- **Debug an issue** → superpowers:systematic-debugging or debugging-toolkit:debugger
- **Write tests** → superpowers:test-driven-development
- **Review code** → superpowers:requesting-code-review
- **Work with Python** → python-best-practices (ALWAYS)
- **Design an API** → backend-development:backend-architect
- **Optimize database** → database-migrations:database-optimizer
- **Deploy infrastructure** → cicd-automation:cloud-architect
- **Document codebase** → cartographer
- **Create parallel work** → superpowers:dispatching-parallel-agents
- **Map a codebase** → cartographer
- **Verify completion** → superpowers:verification-before-completion

---

**Last Updated:** 2026-02-12
**Total Skills:** 100+
**Categories:** 9

**Note:** This is a living document. Skills may be added or updated. Always use the Skill tool to invoke skills - never attempt to manually implement skill functionality.
