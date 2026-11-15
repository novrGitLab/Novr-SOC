// Honest UI states (audit 08 §5): an unreachable backend, a missing session, a forbidden action and an
// empty result are different things and are shown differently. Pure module (unit-tested).

export type UiState = 'unauthorized' | 'forbidden' | 'not_found' | 'validation' | 'conflict' | 'backend_unreachable'
    | 'not_ready' | 'error';

export class ApiError extends Error {
    constructor(public status: number, public code: string, message: string, public requestId = '', public details?: unknown) {
        super(message);
        this.name = 'ApiError';
    }
}

export function uiState(err: unknown): UiState {
    if (!(err instanceof ApiError)) return 'error';
    if (err.code === 'backend_unreachable') return 'backend_unreachable';
    switch (err.status) {
        case 401: return 'unauthorized';
        case 403: return 'forbidden';
        case 404: return 'not_found';
        case 409: return 'conflict';
        case 422: return 'validation';
        case 502: case 504: return 'backend_unreachable';
        case 503: return 'not_ready';
        default: return 'error';
    }
}

export const STATE_TEXT: Record<UiState, { title: string; body: string }> = {
    unauthorized: { title: 'Signed out', body: 'Your session has ended. Sign in again to continue.' },
    forbidden: { title: 'Not available for your role', body: 'Your role or organization does not allow this.' },
    not_found: { title: 'Not found', body: 'It does not exist, or it belongs to an organization you cannot access.' },
    validation: { title: 'Check the form', body: 'Some values are not valid.' },
    conflict: { title: 'Already exists', body: 'Something with the same name already exists.' },
    backend_unreachable: { title: 'Service unreachable', body: 'The NovrSOC API could not be reached. Nothing was changed.' },
    not_ready: { title: 'Service not ready', body: 'The API is running but its database is not ready.' },
    error: { title: 'Something went wrong', body: 'An unexpected error occurred.' },
};

export async function apiErrorFromResponse(res: Response): Promise<ApiError> {
    const requestId = res.headers.get('x-request-id') ?? '';
    try {
        const body = (await res.json()) as { error?: { code?: string; message?: string; request_id?: string; details?: unknown } };
        if (body?.error?.code) {
            return new ApiError(res.status, body.error.code, body.error.message ?? '', body.error.request_id ?? requestId, body.error.details);
        }
    } catch { /* not JSON: a proxy error page */ }
    if (res.status === 502 || res.status === 503 || res.status === 504 || res.status === 500) {
        return new ApiError(res.status === 503 ? 503 : 0, res.status === 503 ? 'not_ready' : 'backend_unreachable',
            'The NovrSOC service could not be reached.', requestId);
    }
    return new ApiError(res.status, 'http_error', `Request failed (${res.status})`, requestId);
}
