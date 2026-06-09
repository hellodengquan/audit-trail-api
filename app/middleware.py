import time
import json
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("audit-trail")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        request_id = request.headers.get("X-Request-ID", "")
        if not request_id:
            import uuid
            request_id = uuid.uuid4().hex[:12]

        logger.info(
            f"[{request_id}] Request started: {request.method} {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )

        try:
            response = await call_next(request)
            process_time = (time.time() - start_time) * 1000
            response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
            response.headers["X-Request-ID"] = request_id

            logger.info(
                f"[{request_id}] Request completed: {response.status_code} "
                f"in {process_time:.2f}ms"
            )

            return response
        except Exception as e:
            process_time = (time.time() - start_time) * 1000
            logger.error(
                f"[{request_id}] Request failed with error: {str(e)} "
                f"after {process_time:.2f}ms",
                exc_info=True
            )
            raise


class CORSMiddlewareWrapper:
    def __init__(self, app, origins=None):
        self.app = app
        from starlette.middleware.cors import CORSMiddleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=origins or ["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["X-Process-Time", "X-Request-ID"],
        )
