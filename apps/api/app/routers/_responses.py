from novrsoc_contracts.v1.common import ErrorResponse

ERRORS = {
    400: {"model": ErrorResponse, "description": "Bad request"},
    401: {"model": ErrorResponse, "description": "Not authenticated"},
    403: {"model": ErrorResponse, "description": "Forbidden (permission, organization or CSRF)"},
    404: {"model": ErrorResponse, "description": "Not found (also returned for another organization's record)"},
    422: {"model": ErrorResponse, "description": "Validation error"},
}
