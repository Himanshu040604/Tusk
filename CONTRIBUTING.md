# Contributing to IAM Policy Sentinel

Thanks for contributing. This document covers the local development loop,
test requirements, and the release process. Sentinel is a security tool
with a fail-closed stance (see `prod_imp.md § 2 Principle 4`), so code
hygiene and audit-trail discipline are non-negotiable.

## Environment setup

- **OS:** WSL2 (Ubuntu) recommended. Native Linux works identically. macOS
  works for most paths but some filesystem-contention tests budget for
  NTFS-backed WSL2 I/O and may run faster than the budget elsewhere.
- **Python:** 3.12 pinned via `.python-version`.
- **Package manager:** `uv` (do NOT use plain `pip install`).
- Clone, then:
  ```bash
  uv sync --all-extras
  ```
  This creates `.venv/`, installs `pyproject.toml` deps, and sets up
  editable installs.

## Running tests

Sentinel has two test-run modes. Both are required to pass before a PR is
merged:

```bash
# Parallel — primary dev loop. ~45s wall time.
uv run pytest -m "not live" -n auto

# Serial — catches shared-state regressions that xdist hides. ~105s wall time.
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

**MUST** use the full invocation:

```bash
uv run mypy src/sentinel --explicit-package-bases
```

A bare `uv run mypy src/` produces `error: Source file found twice under
different module names` because the `src/sentinel/fetchers/` and
`src/sentinel/refresh/` packages share names with top-level modules
under certain `sys.path` permutations.

## Recovering from HMAC key errors

If `sentinel fetch` / `sentinel run` fails with a `HMACError`, the local
`cache.key` is either corrupted, has broad world-permissions (`0o777`),
or is out of sync with an existing cache. Recovery:

```bash
# Rebuild the DB + derive a fresh key
rm data/iam_actions.db
.venv/bin/sentinel info
```

Alternatively, `sentinel cache rotate-key` wipes the cache and regenerates
the key without touching the IAM DB.

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
