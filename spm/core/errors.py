"""Safe error reporting for API responses.

Exception text and stack traces can contain hostnames, ARNs, request details or
upstream error bodies, so they are logged server-side only. API responses get
a fixed message plus an error ID that matches the log line.
"""
from __future__ import annotations

import logging
import secrets

logger = logging.getLogger("spm.errors")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def public_error(context: str) -> str:
    """Log the exception being handled and return a client-safe message.

    Call from inside an ``except`` block. The traceback goes to the server log
    (CloudWatch in ECS); the caller gets only ``"<context> failed (error id ...)"``.
    """
    error_id = secrets.token_hex(4)
    logger.exception("%s failed (error id %s)", context, error_id)
    return f"{context} failed (error id {error_id})"
