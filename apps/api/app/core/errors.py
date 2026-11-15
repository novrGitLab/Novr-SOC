"""Structured errors: every error body is {"error": {"code", "message", "request_id", "details"?}}.

Unexpected exceptions become a 500 with a generic message: no stack trace, SQL or value reaches the
client (the FastAPI equivalent of legacy lib/asyncRouteErrors.ts + index.ts error handler).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import InterfaceError as SAInterfaceError
from sqlalchemy.exc import OperationalError as SAOperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("novrsoc.errors")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any | None = None, headers: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.details, self.headers = status, code, message, details, headers


def unauthenticated(message: str = "Authentication required") -> ApiError:
    return ApiError(401, "unauthenticated", message)


def forbidden(message: str = "Not permitted", details: Any | None = None) -> ApiError:
    return ApiError(403, "forbidden", message, details)


def not_found(message: str = "Not found") -> ApiError:
    return ApiError(404, "not_found", message)


def _body(request: Request, code: str, message: str, details: Any | None = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message, "request_id": getattr(request.state, "request_id", "")}
    if details is not None:
        err["details"] = details
    return {"error": err}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return JSONResponse(_body(request, exc.code, exc.message, exc.details), status_code=exc.status, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        details = [{"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg", ""), "type": e.get("type", "")}
                   for e in exc.errors()]
        return JSONResponse(_body(request, "validation_error", "The request is not valid", details), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed", 401: "unauthenticated", 403: "forbidden"}.get(exc.status_code, "http_error")
        return JSONResponse(_body(request, code, str(exc.detail) if exc.status_code != 404 else "Not found"),
                            status_code=exc.status_code)

    @app.exception_handler(SAOperationalError)
    @app.exception_handler(SAInterfaceError)
    async def _database_unavailable(request: Request, exc: Exception):
        # A connection-level failure (database down, wrong port, refused): a distinct, honest 503 so the
        # UI can say "not ready" instead of "something went wrong". No driver text reaches the client.
        log.error("database unavailable request_id=%s type=%s", getattr(request.state, "request_id", ""), type(exc).__name__)
        return JSONResponse(_body(request, "database_unavailable", "The database is not reachable"), status_code=503)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        log.error("unhandled error request_id=%s type=%s", getattr(request.state, "request_id", ""), type(exc).__name__)
        return JSONResponse(_body(request, "internal_error", "An unexpected error occurred"), status_code=500)
