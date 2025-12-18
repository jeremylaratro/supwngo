"""
supwngo REST API.

Provides HTTP API for binary analysis and exploit generation.

Example:
    # Start API server
    from supwngo.api import create_app, run_server
    app = create_app()
    run_server(app, host="0.0.0.0", port=8080)

    # Or use CLI
    # supwngo api --host 0.0.0.0 --port 8080
"""

from supwngo.api.server import (
    create_app,
    run_server,
    APIConfig,
)
from supwngo.api.models import (
    AnalysisRequest,
    AnalysisResponse,
    ExploitRequest,
    ExploitResponse,
    ROPRequest,
    ROPResponse,
    JobStatus,
    JobResult,
)

__all__ = [
    "create_app",
    "run_server",
    "APIConfig",
    "AnalysisRequest",
    "AnalysisResponse",
    "ExploitRequest",
    "ExploitResponse",
    "ROPRequest",
    "ROPResponse",
    "JobStatus",
    "JobResult",
]
