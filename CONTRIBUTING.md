# Contributing to IAM Policy Sentinel

Thanks for contributing. This document covers the local development loop,
test requirements, and the release process. Sentinel is a security tool
with a fail-closed stance (see `prod_imp.md § 2 Principle 4`), so code
hygiene and audit-trail discipline are non-negotiable.

## Environment setup

- **OS:** WSL2 (Ubuntu) recommended. Native Linux works identically. macOS
  works for most paths but some filesystem-contention tests budget for
  NTFS-backed WSL2 I/O and may run faster than the budget elsewhere.
- **Python:** 3.11+ required (3.12 recommended). Enforced at runtime in
  both `src/sentinel/__init__.py` and `src/sentinel/__main__.py`;
  `pyproject.toml` sets `requires-python = ">=3.11"`.  There is no
  `.python-version` file — `uv sync` respects `requires-python`
  without one.
- **Package manager:** `uv` (do NOT use plain `pip install`).
- Clone, then:
  ```bash
  uv sync --all-extras
  ```
  This creates `.venv/`, installs `pyproject.toml` deps, and sets up
  editable installs.

## Running tests

Sentinel has two test-run modes. Both are required to pass before a PR is
merged. Current working-tree baseline: **856 tests, 1 skipped** (VCR
cassette regen gated behind `-m live`). v0.8.1 shipped at 813; the
v0.8.1 post-ship audit cycle (U1-U33 + H1/H2/SEC-* findings) added the
remaining tests.

```bash
# Parallel — primary dev loop. ~45s wall time.
uv run pytest -m "not live" -n auto

# Serial — catches shared-state regressions that xdist hides. ~110s wall time.
uv run pytest -m "not live"
```

`-m "not live"` is in the default `addopts` (see `pyproject.toml`), so
`live` tests (VCR cassette regen, real-network) are excluded unless you
explicitly pass `-m live`.

## Linting

```bash
uv run ruff check .
uv run ruff format --check .
```

Both must pass. `--fix` can auto-resolve many ruff violations; always
inspect the diff before committing.

## Type checking

```bash
uv run mypy
```

Targets and `explicit_package_bases` live in `pyproject.toml`
`[tool.mypy]` (see `files = ["src/sentinel"]`), so the bare
invocation picks the right scope uniformly across CI, pre-commit,
and local dev. Prior to U32 in the v0.8.1 post-ship audit, CI and
docs called `uv run mypy src/sentinel --explicit-package-bases`
directly, which produced `error: Source file found twice under
different module names` under certain `sys.path` permutations. That
failure mode is resolved by the narrower `files` target plus
`explicit_package_bases = true` in `pyproject.toml`, so the bare
invocation is correct everywhere.

### Cold-start performance gate

`tests/test_performance.py::test_cold_start_budget` enforces
`sentinel --version < MAX_ALLOWED_SECONDS` (currently 0.3 s
steady-state). Measured median after v0.8.1's `C2` deferred-yaml-
import fix: **~113 ms**. If you add a top-level import in any module
that `sentinel/__init__.py` pulls transitively, measure first:

```bash
time .venv/bin/sentinel --version       # median across 5 runs
```

Keep new imports inside function bodies if they pull `pydantic`,
`pydantic-settings`, or any multi-hundred-millisecond subpackage.

## Recovering from HMAC key errors

If `sentinel fetch` / `sentinel run` fails with a `HMACError`, the local
`cache.key` is either corrupted, has broad world-permissions (`0o777`),
or is out of sync with an existing cache.  Recover with the targeted
fix first; the destructive rebuild is a last resort:

```bash
# Preferred: targeted fix — wipe cache entries + regenerate HMAC root
# key.  Does NOT touch data/iam_actions.db (no re-fetch needed).
uv run sentinel cache rotate-key
```

If `rotate-key` does not resolve the error (e.g. the IAM DB itself is
corrupted, not just the cache key), fall back to a full rebuild:

```bash
# Last resort: destroys the IAM DB and forces a full refetch.
rm data/iam_actions.db
uv run sentinel info
```

## Commit conventions

Conventional Commits pattern with issue/finding IDs:

```
type(scope): description (IssueID)

Body: the why, not the what. If the fix is large or subtle, reference
phase8_1_planned.md / prod_imp.md section. Keep lines at ≤ 80 cols.

Co-Authored-By: ...
```

Common scopes:
- `fix`: bug fix, finding fix
- `feat`: new feature
- `sec`: security-relevant change
- `perf`: performance fix
- `refactor`: code cleanup with no behavior change
- `docs`: documentation only
- `test`: test-only change
- `chore`: build, release, hygiene
- `deprecate`: mark something for removal

## Release process

1. **Apply fixes** as small commits (one issue per commit when possible).
2. **Bump version** in `src/sentinel/__init__.py`:
   ```python
   __version__ = "0.8.1"
   ```
3. **Add CHANGELOG entry** in the Keep-a-Changelog format:
   ```markdown
   ## [0.8.1] - YYYY-MM-DD
   ### Fixed
   - ...
   ### Deprecated
   - ...
   ### Internal
   - ...
   ```
4. **Verify green** — both test modes, ruff, mypy, cold-start budget.
5. **Commit release**: `chore(release): v0.8.1`.
6. **Annotated tag**:
   ```bash
   git tag -a v0.8.1 -m "Phase 8.1 — ..."
   ```
7. **Wait for owner approval** before any `git push`. See the GitHub Push
   Approval policy: no push without explicit "yes you can push it" from
   the owner. This applies to `git push`, `git push --tags`, and
   `gh pr create`.

### 3-agent investigation pipeline

Every non-trivial release since v0.6.0 has gone through the same
sequential investigation pipeline before fixes are applied:

1. **Agent 1 — validate + research.** Confirms each finding is genuine
   (not a false positive), researches idiomatic fixes, and records the
   decision trail.
2. **Agent 2 — fit-check.** Ensures proposed fixes align with existing
   patterns (`prod_imp.md § 2` fail-closed principle, Amendment 7
   layout, HMAC domain separation, ephemeral-flag HARD-FAIL, etc.).
3. **Agent 3 — integration.** Catches cross-cutting side effects,
   regressions, and test-harness interactions before commit.

The pattern is intentionally serial (not parallel) so each agent sees
the previous agent's output. See `phase8_1_implementation_report.md`,
`CHANGELOG.md [Unreleased]`, and `prod_imp.md § 17 Amendment 11` for
a worked example across the v0.8.1 maintenance release.
