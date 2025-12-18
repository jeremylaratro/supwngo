"""
supwngo REST API server.

FastAPI-based server for binary analysis and exploit generation.
"""

import asyncio
import base64
import hashlib
import os
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import FastAPI
try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("FastAPI not available. Install with: pip install fastapi uvicorn")

# Import API models
from supwngo.api.models import (
    AnalysisRequest,
    AnalysisResponse,
    ExploitRequest,
    ExploitResponse,
    ROPRequest,
    ROPResponse,
    LibcRequest,
    LibcResponse,
    JobStatus,
    JobResult,
    HealthResponse,
    ProtectionInfo,
    VulnerabilityInfo,
    GadgetInfo,
)


@dataclass
class APIConfig:
    """API server configuration."""
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    max_upload_size: int = 100 * 1024 * 1024  # 100MB
    job_timeout: int = 600  # 10 minutes
    temp_dir: str = ""


@dataclass
class Job:
    """Background job."""
    job_id: str
    job_type: str
    state: str = "pending"
    progress: float = 0.0
    message: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class JobManager:
    """Manage background jobs."""

    def __init__(self):
        self.jobs: Dict[str, Job] = {}

    def create_job(self, job_type: str) -> str:
        """Create a new job."""
        job_id = str(uuid.uuid4())
        self.jobs[job_id] = Job(job_id=job_id, job_type=job_type)
        return job_id

    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID."""
        return self.jobs.get(job_id)

    def update_job(
        self,
        job_id: str,
        state: Optional[str] = None,
        progress: Optional[float] = None,
        message: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """Update job status."""
        job = self.jobs.get(job_id)
        if job:
            if state:
                job.state = state
            if progress is not None:
                job.progress = progress
            if message:
                job.message = message
            if result is not None:
                job.result = result
            if error:
                job.error = error
            job.updated_at = time.time()

    def cleanup_old_jobs(self, max_age: int = 3600):
        """Remove jobs older than max_age seconds."""
        now = time.time()
        to_remove = [
            job_id for job_id, job in self.jobs.items()
            if now - job.created_at > max_age
        ]
        for job_id in to_remove:
            del self.jobs[job_id]


# Global instances
job_manager = JobManager()
start_time = time.time()
jobs_processed = 0


def create_app(config: Optional[APIConfig] = None) -> Any:
    """
    Create FastAPI application.

    Args:
        config: API configuration

    Returns:
        FastAPI app instance
    """
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI required. Install with: pip install fastapi uvicorn")

    config = config or APIConfig()

    app = FastAPI(
        title="supwngo API",
        description="Binary exploitation framework API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health endpoint
    @app.get("/health", response_model=HealthResponse)
    async def health_check():
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            version="1.0.0",
            uptime=time.time() - start_time,
            jobs_processed=jobs_processed,
            jobs_pending=sum(1 for j in job_manager.jobs.values() if j.state == "pending"),
        )

    # Analysis endpoints
    @app.post("/api/analyze", response_model=AnalysisResponse)
    async def analyze_binary(request: AnalysisRequest):
        """
        Analyze a binary for vulnerabilities and protections.

        Provide either binary_path (server-side path) or binary_data (base64 encoded).
        """
        global jobs_processed
        start = time.time()

        try:
            # Get binary path
            binary_path = await _get_binary_path(request.binary_path, request.binary_data)

            # Import analysis modules
            from supwngo.core.binary import Binary
            from supwngo.vulns import detect_vulnerabilities

            # Load binary
            binary = Binary(binary_path)

            # Build response
            response = AnalysisResponse(
                success=True,
                binary_name=binary.path.name,
                architecture=binary.arch,
                bits=binary.bits,
                protections=ProtectionInfo(
                    nx=binary.protections.nx,
                    pie=binary.protections.pie,
                    canary=binary.protections.canary,
                    relro=binary.protections.relro or "None",
                ),
                dangerous_functions=[f.name for f in binary.dangerous_functions[:20]],
                symbols_count=len(binary.symbols),
                analysis_time=time.time() - start,
            )

            # Run vulnerability detection if requested
            if "vulns" in request.analysis_types:
                vulns = detect_vulnerabilities(binary)
                response.vulnerabilities = [
                    VulnerabilityInfo(
                        vuln_type=v.vuln_type.value if hasattr(v.vuln_type, 'value') else str(v.vuln_type),
                        severity=v.severity if hasattr(v, 'severity') else "medium",
                        location=str(v.location) if hasattr(v, 'location') else "",
                        description=v.description if hasattr(v, 'description') else "",
                        confidence=v.confidence if hasattr(v, 'confidence') else 0.5,
                    )
                    for v in vulns[:20]
                ]

            jobs_processed += 1
            return response

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return AnalysisResponse(
                success=False,
                error=str(e),
                analysis_time=time.time() - start,
            )

    @app.post("/api/analyze/async")
    async def analyze_binary_async(
        request: AnalysisRequest,
        background_tasks: BackgroundTasks
    ):
        """Start async binary analysis."""
        job_id = job_manager.create_job("analysis")
        background_tasks.add_task(_run_analysis_job, job_id, request)
        return {"job_id": job_id, "status": "pending"}

    # Exploit generation endpoints
    @app.post("/api/exploit", response_model=ExploitResponse)
    async def generate_exploit(request: ExploitRequest):
        """
        Generate exploit for a binary.

        Automatically detects vulnerability type if not specified.
        """
        global jobs_processed
        start = time.time()

        try:
            binary_path = await _get_binary_path(request.binary_path, request.binary_data)

            from supwngo.core.binary import Binary
            from supwngo.exploit.auto import AutoExploit

            binary = Binary(binary_path)
            auto = AutoExploit(binary)

            # Generate exploit
            result = auto.generate_exploit(
                vuln_type=request.vuln_type,
                target_func=request.target_function,
            )

            if result:
                payload_b64 = base64.b64encode(result.payload).decode() if result.payload else None
                payload_hex = result.payload.hex() if result.payload else None

                jobs_processed += 1
                return ExploitResponse(
                    success=True,
                    exploit_type=result.exploit_type if hasattr(result, 'exploit_type') else "auto",
                    payload=payload_b64,
                    payload_hex=payload_hex,
                    script=result.script if hasattr(result, 'script') else None,
                    notes=result.notes if hasattr(result, 'notes') else [],
                    generation_time=time.time() - start,
                )
            else:
                return ExploitResponse(
                    success=False,
                    error="Could not generate exploit",
                    generation_time=time.time() - start,
                )

        except Exception as e:
            logger.error(f"Exploit generation error: {e}")
            return ExploitResponse(
                success=False,
                error=str(e),
                generation_time=time.time() - start,
            )

    # ROP chain endpoints
    @app.post("/api/rop", response_model=ROPResponse)
    async def build_rop_chain(request: ROPRequest):
        """Build ROP chain for a binary."""
        global jobs_processed
        start = time.time()

        try:
            binary_path = await _get_binary_path(request.binary_path, request.binary_data)

            from supwngo.core.binary import Binary
            from supwngo.exploit.rop import ROPChainBuilder

            binary = Binary(binary_path)
            builder = ROPChainBuilder(binary)

            # Build chain based on type
            if request.chain_type == "execve":
                chain = builder.build_execve_chain()
            elif request.chain_type == "mprotect":
                chain = builder.build_mprotect_chain()
            else:
                chain = builder.build_ret2libc_chain()

            if chain:
                chain_bytes = chain.build() if hasattr(chain, 'build') else bytes(chain)
                chain_b64 = base64.b64encode(chain_bytes).decode()

                jobs_processed += 1
                return ROPResponse(
                    success=True,
                    chain=chain_b64,
                    chain_hex=chain_bytes.hex(),
                    chain_length=len(chain_bytes),
                    gadgets_used=[
                        GadgetInfo(
                            address=g.address,
                            instructions=g.instructions if hasattr(g, 'instructions') else str(g),
                        )
                        for g in (chain.gadgets if hasattr(chain, 'gadgets') else [])[:20]
                    ],
                )
            else:
                return ROPResponse(
                    success=False,
                    error="Could not build ROP chain",
                )

        except Exception as e:
            logger.error(f"ROP chain error: {e}")
            return ROPResponse(
                success=False,
                error=str(e),
            )

    # Libc identification
    @app.post("/api/libc", response_model=LibcResponse)
    async def identify_libc(request: LibcRequest):
        """Identify libc from leaked addresses."""
        try:
            from supwngo.remote.libc_db import LibcDB

            db = LibcDB()
            result = db.lookup(request.symbols)

            if result:
                return LibcResponse(
                    success=True,
                    libc_id=result.id if hasattr(result, 'id') else None,
                    libc_name=result.name if hasattr(result, 'name') else None,
                    download_url=result.download_url if hasattr(result, 'download_url') else None,
                    symbols=result.symbols if hasattr(result, 'symbols') else {},
                    buildid=result.buildid if hasattr(result, 'buildid') else None,
                )
            else:
                return LibcResponse(
                    success=False,
                    error="Libc not found",
                )

        except Exception as e:
            logger.error(f"Libc lookup error: {e}")
            return LibcResponse(
                success=False,
                error=str(e),
            )

    # Job status endpoints
    @app.get("/api/jobs/{job_id}", response_model=JobStatus)
    async def get_job_status(job_id: str):
        """Get status of an async job."""
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        return JobStatus(
            job_id=job.job_id,
            state=job.state,
            progress=job.progress,
            message=job.message,
            created_at=str(job.created_at),
            updated_at=str(job.updated_at),
            result=job.result,
        )

    @app.delete("/api/jobs/{job_id}")
    async def cancel_job(job_id: str):
        """Cancel a pending job."""
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        if job.state == "pending":
            job_manager.update_job(job_id, state="cancelled")
            return {"status": "cancelled"}
        else:
            return {"status": job.state, "message": "Job already started or completed"}

    # File upload endpoint
    @app.post("/api/upload")
    async def upload_binary(file: UploadFile = File(...)):
        """Upload a binary file for analysis."""
        try:
            # Create temp file
            temp_dir = config.temp_dir or tempfile.gettempdir()
            file_hash = hashlib.sha256(await file.read()).hexdigest()[:16]
            await file.seek(0)

            temp_path = Path(temp_dir) / f"supwngo_{file_hash}"
            temp_path.write_bytes(await file.read())

            return {
                "success": True,
                "path": str(temp_path),
                "filename": file.filename,
                "size": temp_path.stat().st_size,
            }

        except Exception as e:
            logger.error(f"Upload error: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    return app


async def _get_binary_path(
    binary_path: Optional[str],
    binary_data: Optional[str]
) -> str:
    """Get binary path from request (path or base64 data)."""
    if binary_path:
        if not Path(binary_path).exists():
            raise HTTPException(status_code=404, detail="Binary not found")
        return binary_path

    elif binary_data:
        # Decode base64 and save to temp file
        try:
            data = base64.b64decode(binary_data)
            file_hash = hashlib.sha256(data).hexdigest()[:16]
            temp_path = Path(tempfile.gettempdir()) / f"supwngo_{file_hash}"
            temp_path.write_bytes(data)
            return str(temp_path)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid binary data: {e}")

    else:
        raise HTTPException(status_code=400, detail="Provide binary_path or binary_data")


async def _run_analysis_job(job_id: str, request: AnalysisRequest):
    """Run analysis job in background."""
    job_manager.update_job(job_id, state="running", message="Starting analysis")

    try:
        binary_path = await _get_binary_path(request.binary_path, request.binary_data)

        job_manager.update_job(job_id, progress=0.2, message="Loading binary")

        from supwngo.core.binary import Binary
        binary = Binary(binary_path)

        job_manager.update_job(job_id, progress=0.5, message="Analyzing protections")

        result = {
            "binary_name": binary.path.name,
            "architecture": binary.arch,
            "bits": binary.bits,
            "protections": {
                "nx": binary.protections.nx,
                "pie": binary.protections.pie,
                "canary": binary.protections.canary,
                "relro": binary.protections.relro,
            },
            "dangerous_functions": [f.name for f in binary.dangerous_functions[:20]],
        }

        if "vulns" in request.analysis_types:
            job_manager.update_job(job_id, progress=0.7, message="Detecting vulnerabilities")
            from supwngo.vulns import detect_vulnerabilities
            vulns = detect_vulnerabilities(binary)
            result["vulnerabilities"] = [
                {"type": str(v.vuln_type), "description": v.description}
                for v in vulns[:20]
            ]

        job_manager.update_job(
            job_id,
            state="completed",
            progress=1.0,
            message="Analysis complete",
            result=result
        )

    except Exception as e:
        logger.error(f"Job {job_id} failed: {e}")
        job_manager.update_job(
            job_id,
            state="failed",
            error=str(e)
        )


def run_server(
    app: Any = None,
    host: str = "0.0.0.0",
    port: int = 8080,
    reload: bool = False
):
    """
    Run the API server.

    Args:
        app: FastAPI app (creates one if None)
        host: Host to bind to
        port: Port to listen on
        reload: Enable auto-reload for development
    """
    try:
        import uvicorn
    except ImportError:
        raise ImportError("uvicorn required. Install with: pip install uvicorn")

    if app is None:
        app = create_app()

    logger.info(f"Starting supwngo API server on {host}:{port}")
    uvicorn.run(app, host=host, port=port, reload=reload)
