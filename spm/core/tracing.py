"""OpenTelemetry tracing setup.

Exports spans via OTLP to an ADOT (AWS Distro for OpenTelemetry) sidecar, which
forwards them to AWS X-Ray. If the exporter cannot be initialized, tracing is
silently disabled so the service keeps running.
"""
from __future__ import annotations

import logging
import os

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

logger = logging.getLogger("spm.tracing")

OTEL_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "ai-spm")


def init_tracing(service_name: str | None = None) -> trace.Tracer:
    """Initialize OpenTelemetry with an OTLP exporter pointing at the ADOT sidecar."""
    name = service_name or SERVICE_NAME
    resource = Resource.create({"service.name": name})
    provider = TracerProvider(resource=resource)
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter(endpoint=OTEL_ENDPOINT, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
    except Exception as e:  # pragma: no cover - tracing is best-effort
        logger.warning("OTLP exporter init failed (tracing disabled): %s", e)
    trace.set_tracer_provider(provider)
    return trace.get_tracer(name)


def get_tracer(name: str = "ai-spm") -> trace.Tracer:
    return trace.get_tracer(name)
