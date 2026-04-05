import api from './api';
import type {
  Policy,
  PolicyCreateRequest,
  NLPPolicyParse,
  PolicySimulationRequest,
  PolicySimulationResponse,
} from '../types';

export const policyService = {
  async getAll(): Promise<Policy[]> {
    const res = await api.get<Policy[]>('/policies');
    return res.data;
  },

  async getByEndpoint(endpointId: string): Promise<Policy[]> {
    const res = await api.get<Policy[]>(`/policies/endpoint/${endpointId}`);
    return res.data;
  },

  async create(data: PolicyCreateRequest): Promise<Policy> {
    const res = await api.post<Policy>('/policies', data);
    return res.data;
  },

  async delete(id: string): Promise<void> {
    await api.delete(`/policies/${id}`);
  },

  async toggle(id: string): Promise<Policy> {
    const res = await api.patch<Policy>(`/policies/${id}/toggle`, {});
    return res.data;
  },

  async parseNaturalLanguage(input: string): Promise<NLPPolicyParse> {
    const res = await api.post<NLPPolicyParse>('/policies/parse', { input });
    return res.data;
  },

  async simulate(data: PolicySimulationRequest): Promise<PolicySimulationResponse> {
    const res = await api.post<PolicySimulationResponse>('/policies/simulate', data);
    return res.data;
  },
};
