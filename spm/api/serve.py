"""Start the SPM API with uvicorn: ``python -m spm.api.serve``.

Binds to ``SPM_API_HOST`` (default ``127.0.0.1``) on ``SPM_API_PORT`` (default
8001). Refuses to start when ``SPM_AUTH_DISABLED=true`` unless the bind address
is loopback and the process is not running in ECS. The container image sets
``SPM_API_HOST=0.0.0.0`` (the port is exposed only through the ECS task network
and ALB target group), so the image can never run with authentication off.
"""
from __future__ import annotations

import os
import sys

import uvicorn

from spm.core.auth import assert_auth_disabled_is_local


def main() -> None:
    host = os.getenv("SPM_API_HOST", "127.0.0.1")
    port = int(os.getenv("SPM_API_PORT", "8001"))
    try:
        assert_auth_disabled_is_local(host)
    except RuntimeError as e:
        print(f"[SPM] refusing to start: {e}", file=sys.stderr)
        sys.exit(2)
    uvicorn.run("spm.api.main:app", host=host, port=port, proxy_headers=False)


if __name__ == "__main__":
    main()
