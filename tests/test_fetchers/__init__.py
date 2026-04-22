"""Per-fetcher tests for Phase 4 ingestion sources.

Each module targets one concrete fetcher + shared helpers.  Tests that
genuinely need a recorded HTTP cassette are marked ``@pytest.mark.vcr``
and will be recorded by the next nightly ``live-tests`` run (M21); see
``prod_imp.md`` § 10.3.
"""
