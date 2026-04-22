# Pipeline output snapshots

Each `*.snapshot` file is a canonical JSON dump of pipeline output for the
corresponding fixture in `tests/fixtures/test_policies/`.

## Regenerate all snapshots

```
SENTINEL_REGEN_SNAPSHOTS=1 uv run pytest tests/test_snapshots.py
```

## Regenerate one snapshot

```
SENTINEL_REGEN_SNAPSHOTS=1 uv run pytest tests/test_snapshots.py::test_wildcard_overuse
```

Snapshots are self-creating on first run — if the `.snapshot` file is missing,
the test creates it and skips with a notice to re-run.
