import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Server,
  ArrowLeft,
  Wifi,
  WifiOff,
  AlertTriangle,
  AppWindow,
  Clock,
  Shield,
  Activity,
  Globe,
} from 'lucide-react';
import { Card, CardContent, CardHeader } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Skeleton, StatCardSkeleton } from '../components/ui/Skeleton';
import { endpointService } from '../services/endpoint.service';
import type { Endpoint, Application, Alert } from '../types';

const POLL_INTERVAL_MS = 30_000; // auto-refresh every 30 seconds

const statusConfig: Record<
  Endpoint['status'],
  { variant: 'success' | 'danger' | 'warning'; label: string; icon: React.ReactNode }
> = {
  active: { variant: 'success', label: 'Active', icon: <Wifi size={14} /> },
  inactive: { variant: 'danger', label: 'Inactive', icon: <WifiOff size={14} /> },
  warning: { variant: 'warning', label: 'Warning', icon: <AlertTriangle size={14} /> },
};

const appStatusVariant: Record<Application['status'], 'success' | 'danger'> = {
  running: 'success',
  stopped: 'danger',
};

const severityVariant: Record<Alert['severity'], 'danger' | 'warning' | 'info' | 'default'> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
  info: 'default',
};

const EndpointDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [endpoint, setEndpoint] = useState<Endpoint | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval>>();

  const fetchEndpoint = useCallback(async (silent = false) => {
    if (!id) return;
    try {
      if (!silent) setLoading(true);
      setError(null);
      const data = await endpointService.getById(id);
      setEndpoint((prev) => {
        if (prev && prev.status !== data.status) {
          console.info(
            '[EndpointDetail] Status changed: %s → %s',
            prev.status, data.status
          );
        }
        if (prev) {
          console.debug(
            '[EndpointDetail] Refreshed: apps=%d, alerts=%d, traffic=%d',
            data.applications?.length ?? 0,
            data.recent_alerts?.length ?? 0,
            data.traffic_logs ?? 0
          );
        }
        return data;
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to fetch endpoint details';
      console.error('[EndpointDetail] Fetch error:', message);
      setError(message);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [id]);

  // Initial fetch + polling
  useEffect(() => {
    fetchEndpoint();
    pollTimer.current = setInterval(() => fetchEndpoint(true), POLL_INTERVAL_MS);
    console.debug('[EndpointDetail] Polling started for id=%s', id);
    return () => {
      clearInterval(pollTimer.current);
      console.debug('[EndpointDetail] Polling stopped');
    };
  }, [fetchEndpoint, id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 p-6 lg:p-8">
        <Skeleton className="h-8 w-48 mb-8" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          {Array.from({ length: 4 }).map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
        <Skeleton className="h-64 w-full mb-6" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error || !endpoint) {
    return (
      <div className="min-h-screen bg-slate-900 p-6 lg:p-8">
        <Button variant="ghost" icon={<ArrowLeft size={16} />} onClick={() => navigate('/endpoints')}>
          Back to Endpoints
        </Button>
        <Card className="mt-6 border-red-500/30">
          <CardContent className="py-12 text-center">
            <AlertTriangle className="mx-auto text-red-400 mb-4" size={40} />
            <h3 className="text-lg font-medium text-slate-200 mb-1">Error Loading Endpoint</h3>
            <p className="text-slate-400 text-sm">{error || 'Endpoint not found'}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const cfg = statusConfig[endpoint.status];

  return (
    <div className="min-h-screen bg-slate-900 p-6 lg:p-8">
      {/* Back button */}
      <Button
        variant="ghost"
        icon={<ArrowLeft size={16} />}
        onClick={() => navigate('/endpoints')}
        className="mb-6"
      >
        Back to Endpoints
      </Button>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-lg bg-blue-500/10 flex items-center justify-center">
            <Server size={24} className="text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">{endpoint.name}</h1>
            <p className="text-slate-400 font-mono text-sm">{endpoint.ip_address}</p>
          </div>
        </div>
        <Button
          variant="primary"
          icon={<Shield size={16} />}
          onClick={() => navigate(`/policies/new?endpoint=${endpoint.id}`)}
        >
          Create Policy for Endpoint
        </Button>
      </div>

      {/* Info Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <Card>
          <CardContent className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-md bg-blue-500/10 flex items-center justify-center">
              {cfg.icon}
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider">Status</p>
              <Badge variant={cfg.variant} dot>
                {cfg.label}
              </Badge>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-md bg-blue-500/10 flex items-center justify-center">
              <AppWindow size={18} className="text-blue-400" />
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider">Applications</p>
              <p className="text-xl font-bold text-slate-100">{endpoint.applications?.length ?? 0}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-md bg-amber-500/10 flex items-center justify-center">
              <Activity size={18} className="text-amber-400" />
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider">Traffic Logs</p>
              <p className="text-xl font-bold text-slate-100">
                {endpoint.traffic_logs?.toLocaleString() ?? 0}
              </p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-md bg-purple-500/10 flex items-center justify-center">
              <Clock size={18} className="text-purple-400" />
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider">Created</p>
              <p className="text-sm font-medium text-slate-200">
                {new Date(endpoint.created_at).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                })}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Applications */}
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <AppWindow size={18} className="text-blue-400" />
              Applications
            </h2>
          </CardHeader>
          <CardContent>
            {(!endpoint.applications || endpoint.applications.length === 0) ? (
              <div className="text-center py-8">
                <AppWindow className="mx-auto text-slate-500 mb-3" size={36} />
                <p className="text-slate-400 text-sm">No applications registered</p>
              </div>
            ) : (
              <div className="space-y-3">
                {endpoint.applications.map((app) => (
                  <div
                    key={app.id}
                    className="flex items-center justify-between p-3 rounded-md bg-slate-700/30 border border-slate-700/30 hover:border-slate-600/40 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center">
                        <AppWindow size={14} className="text-blue-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-slate-200">{app.name}</p>
                        <p className="text-xs text-slate-500 font-mono">{app.process_name}</p>
                      </div>
                    </div>
                    <Badge variant={appStatusVariant[app.status]} dot>
                      {app.status}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Alerts */}
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <AlertTriangle size={18} className="text-amber-400" />
              Recent Alerts
            </h2>
          </CardHeader>
          <CardContent>
            {(!endpoint.recent_alerts || endpoint.recent_alerts.length === 0) ? (
              <div className="text-center py-8">
                <Shield className="mx-auto text-slate-500 mb-3" size={36} />
                <p className="text-slate-400 text-sm">No recent alerts -- all clear</p>
              </div>
            ) : (
              <div className="space-y-3">
                {endpoint.recent_alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="p-3 rounded-md bg-slate-700/30 border border-slate-700/30"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <Badge variant={severityVariant[alert.severity]}>
                        {alert.severity.toUpperCase()}
                      </Badge>
                      <span className="text-xs text-slate-500">
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm text-slate-200 mb-1">{alert.message}</p>
                    <div className="flex items-center gap-3 text-xs text-slate-500">
                      {alert.attack_type && (
                        <span className="flex items-center gap-1">
                          <Globe size={12} />
                          {alert.attack_type}
                        </span>
                      )}
                      {alert.app_name && (
                        <span className="flex items-center gap-1">
                          <AppWindow size={12} />
                          {alert.app_name}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Policies Section */}
      {endpoint.policies && endpoint.policies.length > 0 && (
        <Card className="mt-6">
          <CardHeader>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Shield size={18} className="text-blue-400" />
              Active Policies
            </h2>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {endpoint.policies.map((policy) => (
                <div
                  key={policy.id}
                  className="flex items-center justify-between p-3 rounded-md bg-slate-700/30 border border-slate-700/30 hover:border-slate-600/40 transition-colors cursor-pointer"
                  onClick={() => navigate(`/policies`)}
                >
                  <div>
                    <p className="text-sm font-medium text-slate-200">{policy.name}</p>
                    <p className="text-xs text-slate-500">{policy.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={policy.purpose === 'block' ? 'danger' : 'success'}>
                      {policy.purpose}
                    </Badge>
                    {policy.is_active && (
                      <Badge variant="info" dot>
                        Active
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default EndpointDetail;
