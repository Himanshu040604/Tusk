"""Coverage tests for ``sentinel.telemetry`` (U33).

The module is a 30-line OpenTelemetry wiring stub — it exposes a single
module-level ``tracer = trace.get_tracer("sentinel")`` which all net /
pipeline code imports for span creation.  These tests exist so future
refactors that accidentally break the import surface or span-context
semantics fail loudly rather than silently dropping telemetry.
"""

from __future__ import annotations

from sentinel.telemetry import tracer


class TestTracer:
    """Smoke tests for the module-level tracer."""

    def test_tracer_exists(self) -> None:
        assert tracer is not None

    def test_tracer_start_as_current_span_is_context_manager(self) -> None:
        """Confirms the API shape net/client.py depends on."""
        with tracer.start_as_current_span("test-span") as span:
            assert span is not None

    def test_tracer_nested_spans_work(self) -> None:
        """Exercises the real usage pattern in
        ``net.client._fetch_live`` where a ``net.request`` span wraps
        per-attempt child spans.  ProxyTracer must tolerate nesting."""
        with tracer.start_as_current_span("outer"):
            with tracer.start_as_current_span("inner") as inner:
                assert inner is not None

    def test_tracer_attributes_can_be_set(self) -> None:
        """Spans in net/client.py set ``http.url``, ``sentinel.source``,
        ``http.status_code`` — confirm set_attribute does not raise."""
        with tracer.start_as_current_span("attr-test") as span:
            # No assertion on stored value; ProxyTracer may be a no-op.
            # The test asserts only that set_attribute is callable.
            span.set_attribute("test.key", "test.value")
            span.set_attribute("test.int", 42)
