import api from './api';
import type { Alert, AttackStats } from '../types';

export const alertService = {
  async getAll(params?: {
    endpoint_id?: string;
    app_id?: string;
    severity?: string;
    limit?: number;
  }): Promise<Alert[]> {
    const res = await api.get<Alert[]>('/alerts', { params });
    return res.data;
  },

  async getByEndpointApp(endpointId: string, appId: string): Promise<Alert[]> {
    const res = await api.get<Alert[]>(`/alerts/endpoint/${endpointId}/app/${appId}`);
    return res.data;
  },

  async getAttackStats(endpointId: string): Promise<AttackStats[]> {
    const res = await api.get<AttackStats[]>(`/attacks/endpoint/${endpointId}`);
    return res.data;
  },

  async getAppAttackStats(endpointId: string, appName: string): Promise<AttackStats[]> {
    const res = await api.get<AttackStats[]>(`/attacks/endpoint/${endpointId}/app/${appName}`);
    return res.data;
  },

  async markFalsePositive(alertId: string, note?: string): Promise<{ status: string }> {
    const res = await api.post<{ status: string }>(`/alerts/${alertId}/false-positive`, { note });
    return res.data;
  },

  async whitelist(
    alertId: string,
    payload: { target_type: 'ip' | 'domain' | 'app'; target_value?: string; note?: string }
  ): Promise<{ status: string }> {
    const res = await api.post<{ status: string }>(`/alerts/${alertId}/whitelist`, payload);
    return res.data;
  },

  async silenceRule(
    alertId: string,
    payload: { policy_id?: string; note?: string }
  ): Promise<{ status: string }> {
    const res = await api.post<{ status: string }>(`/alerts/${alertId}/silence-rule`, payload);
    return res.data;
  },

  async getTuningSummary(): Promise<Record<string, unknown>> {
    const res = await api.get<Record<string, unknown>>('/alerts/feedback/tuning-summary');
    return res.data;
  },
};
