// Endpoint-management API (workstream C module, read through FastAPI; the browser never talks to Wazuh).
import { request, type Schemas } from '@/foundation/api/client';
import { fillPath, type ApiPath } from '@/foundation/api/paths';

export type EndpointInventory = Schemas['EndpointInventory'];
export type EndpointDetail = Schemas['EndpointDetail'];

const P = {
    endpoints: '/api/v1/endpoints',
    endpoint: '/api/v1/endpoints/{agent_id}',
} as const satisfies Record<string, ApiPath>;

export const endpointsApi = {
    inventory: (orgId: string | null) => request<EndpointInventory>(P.endpoints, { orgId }),
    detail: (orgId: string | null, agentId: string) => request<EndpointDetail>(fillPath(P.endpoint, { agent_id: agentId }), { orgId }),
};
