"""OpenTelemetry tracer stub.

I2 note — why the module-level binding is intentional.

``opentelemetry.trace.get_tracer()`` called before an SDK is installed returns
a ``ProxyTracer`` instance.  The ProxyTracer re-resolves the real tracer
provider **lazily on every span-creation call**, not at ``get_tracer()`` time.
That means when a user later installs ``opentelemetry-sdk`` + an exporter and
sets ``OTEL_EXPORTER_OTLP_ENDPOINT``, the existing module-level ``tracer``
reference automatically picks up the real provider — no code changes here.

Phase 1 ships only ``opentelemetry-api`` (50 KB).  The SDK and exporters are
not dependencies; they light up opt-in when users install them.

Usage (from any caller):

    from sentinel.telemetry import tracer

    with tracer.start_as_current_span("pipeline.validate"):
        ...
"""

from __future__ import annotations

from opentelemetry import trace

# Module-level binding is safe thanks to ProxyTracer's lazy resolution.
tracer = trace.get_tracer("sentinel")

__all__ = ["tracer"]
