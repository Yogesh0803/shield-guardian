import api from './api';
import type { Endpoint } from '../types';

export const endpointService = {
  async getAll(): Promise<Endpoint[]> {
    console.debug('[EndpointService] Fetching all endpoints...');
    const res = await api.get<Endpoint[]>('/endpoints');
    console.debug('[EndpointService] Fetched %d endpoints', res.data.length);
    return res.data;
  },

  async getById(id: string): Promise<Endpoint> {
    console.debug('[EndpointService] Fetching endpoint id=%s', id);
    const res = await api.get<Endpoint>(`/endpoints/${id}`);
    console.debug('[EndpointService] Endpoint loaded:', res.data.name, 'status:', res.data.status);
    return res.data;
  },

  async addApp(endpointId: string, appName: string, processName?: string): Promise<void> {
    console.debug('[EndpointService] Adding app "%s" to endpoint %s', appName, endpointId);
    await api.post(`/endpoints/${endpointId}/apps`, {
      name: appName,
      ...(processName ? { process_name: processName } : {}),
    });
    console.debug('[EndpointService] App "%s" added successfully', appName);
  },
};
