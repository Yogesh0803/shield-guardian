import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle,
  Bell,
  Filter,
  ChevronDown,
  ChevronUp,
  Clock,
  AppWindow,
  Globe,
  Server,
  Zap,
  ShieldAlert,
  Info,
  Wifi,
  WifiOff,
  ShieldCheck,
  List,
  Ban,
  CheckCircle2,
  VolumeX,
  Shield,
} from 'lucide-react';
import { Card, CardContent, CardHeader } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Select } from '../components/ui/Input';
import { Skeleton, TableSkeleton } from '../components/ui/Skeleton';
import { alertService } from '../services/alert.service';
import { endpointService } from '../services/endpoint.service';
import { useWebSocket } from '../hooks/useWebSocket';
import type { Alert, Endpoint, FlowContext, WSAlertMessage } from '../types';

const severityConfig: Record<
  Alert['severity'],
  { variant: 'danger' | 'warning' | 'info' | 'default'; icon: React.ReactNode }
> = {
  critical: { variant: 'danger', icon: <ShieldAlert size={14} /> },
  high: { variant: 'danger', icon: <AlertTriangle size={14} /> },
  medium: { variant: 'warning', icon: <Zap size={14} /> },
  low: { variant: 'info', icon: <Info size={14} /> },
  info: { variant: 'default', icon: <Bell size={14} /> },
};

const FlowContextDetail: React.FC<{ context?: FlowContext }> = ({ context }) => {
  if (!context) return <p className="text-sm text-slate-500">No context available</p>;
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 mt-3">
      {[
        { label: 'App Name', value: context.app_name },
        { label: 'Process ID', value: context.process_id },
        { label: 'Trust Score', value: context.app_trust_score?.toFixed(2) },
        { label: 'Hour', value: context.hour },
        { label: 'Day of Week', value: context.day_of_week },
        { label: 'Business Hours', value: context.is_business_hours ? 'Yes' : 'No' },
        { label: 'Rate Deviation', value: context.rate_deviation?.toFixed(3) },
        { label: 'Size Deviation', value: context.size_deviation?.toFixed(3) },
        { label: 'Dest Novelty', value: context.destination_novelty?.toFixed(3) },
        { label: 'Baseline Profile', value: context.baseline_profile_key },
        { label: 'Time Bucket', value: context.baseline_time_bucket },
        { label: '7d Baseline Drift', value: context.baseline_changed_7d ? 'Yes' : 'No' },
        { label: 'Drift Score', value: context.baseline_change_score?.toFixed(3) },
        { label: 'Drift Reason', value: context.baseline_change_reason },
        { label: 'Dest Country', value: context.dest_country },
        { label: 'Dest ASN', value: context.dest_asn },
        { label: 'Geo Anomaly', value: context.is_geo_anomaly ? 'Yes' : 'No' },
      ].map((item) => (
        <div key={item.label} className="p-2 rounded-lg bg-slate-700/30">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider">{item.label}</p>
          <p className="text-xs text-slate-200 font-medium mt-0.5">{item.value ?? '--'}</p>
        </div>
      ))}
    </div>
  );
};

const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [policySilenceByAlert, setPolicySilenceByAlert] = useState<Record<string, string>>({});
  const [domainWhitelistByAlert, setDomainWhitelistByAlert] = useState<Record<string, string>>({});

  // Filters
  const [severityFilter, setSeverityFilter] = useState('');
  const [endpointFilter, setEndpointFilter] = useState('');

  // Real-time alert indicator
  const [newAlertFlash, setNewAlertFlash] = useState(false);

  // WebSocket for real-time alerts
  const handleWsMessage = useCallback((data: unknown) => {
    const msg = data as WSAlertMessage;
    if (msg.type === 'alert' && msg.data) {
      setAlerts((prev) => [msg.data, ...prev]);
      setNewAlertFlash(true);
      setTimeout(() => setNewAlertFlash(false), 2000);
    }
  }, []);

  const { isConnected } = useWebSocket({
    path: '/ws/alerts',
    onMessage: handleWsMessage,
  });

  useEffect(() => {
    fetchData();
  }, [severityFilter, endpointFilter]);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [alertData, endpointData] = await Promise.all([
        alertService.getAll({
          ...(severityFilter ? { severity: severityFilter } : {}),
          ...(endpointFilter ? { endpoint_id: endpointFilter } : {}),
        }),
        endpointService.getAll(),
      ]);
      setAlerts(alertData);
      setEndpoints(endpointData);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to fetch alerts';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const runAction = async (alertId: string, op: () => Promise<unknown>, successMsg: string) => {
    try {
      setActionError(null);
      setActionSuccess(null);
      setActionLoadingId(alertId);
      await op();
      setActionSuccess(successMsg);
      await fetchData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Action failed';
      setActionError(message);
    } finally {
      setActionLoadingId(null);
    }
  };

  const endpointOptions = [
    { value: '', label: 'All Endpoints' },
    ...endpoints.map((ep) => ({ value: ep.id, label: ep.name })),
  ];

  const severityOptions = [
    { value: '', label: 'All Severities' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'info', label: 'Info' },
  ];

  return (
    <div className="min-h-screen bg-slate-900 p-6 lg:p-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <AlertTriangle className="text-blue-500" size={28} />
            Alerts
            {newAlertFlash && (
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
            )}
          </h1>
          <p className="text-slate-400 mt-1">Monitor security events and threat detections</p>
        </div>
        <Badge variant={isConnected ? 'success' : 'danger'} dot>
          {isConnected ? (
            <span className="flex items-center gap-1">
              <Wifi size={12} /> Live
            </span>
          ) : (
            <span className="flex items-center gap-1">
              <WifiOff size={12} /> Disconnected
            </span>
          )}
        </Badge>
      </div>

      {/* Filters */}
      <Card className="mb-6">
        <CardContent>
          <div className="flex items-center gap-2 mb-3">
            <Filter size={16} className="text-slate-400" />
            <span className="text-sm font-medium text-slate-300">Filters</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <Select
              label="Severity"
              options={severityOptions}
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            />
            <Select
              label="Endpoint"
              options={endpointOptions}
              value={endpointFilter}
              onChange={(e) => setEndpointFilter(e.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      {/* Error */}
      {error && (
        <Card className="mb-6 border-red-500/30">
          <CardContent>
            <p className="text-red-400 text-sm">{error}</p>
          </CardContent>
        </Card>
      )}

      {actionSuccess && (
        <Card className="mb-6 border-emerald-500/30">
          <CardContent>
            <p className="text-emerald-400 text-sm">{actionSuccess}</p>
          </CardContent>
        </Card>
      )}

      {actionError && (
        <Card className="mb-6 border-red-500/30">
          <CardContent>
            <p className="text-red-400 text-sm">{actionError}</p>
          </CardContent>
        </Card>
      )}

      {/* Loading */}
      {loading && (
        <Card>
          <CardContent>
            <TableSkeleton rows={8} />
          </CardContent>
        </Card>
      )}

      {/* Empty */}
      {!loading && !error && alerts.length === 0 && (
        <Card>
          <CardContent className="py-16 text-center">
            <Bell className="mx-auto text-slate-500 mb-4" size={48} />
            <h3 className="text-lg font-medium text-slate-300 mb-1">No Alerts Found</h3>
            <p className="text-slate-500 text-sm">
              {severityFilter || endpointFilter
                ? 'Try adjusting your filters'
                : 'No security alerts have been generated yet'}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Alert List */}
      {!loading && alerts.length > 0 && (
        <div className="space-y-2">
          {alerts.map((alert) => {
            const cfg = severityConfig[alert.severity];
            const isExpanded = expandedId === alert.id;
            return (
              <Card key={alert.id} hover>
                <div
                  className="px-5 py-4 cursor-pointer"
                  onClick={() => toggleExpand(alert.id)}
                >
                  <div className="flex items-start gap-4">
                    {/* Severity icon */}
                    <div
                      className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${
                        alert.severity === 'critical' || alert.severity === 'high'
                          ? 'bg-red-500/10'
                          : alert.severity === 'medium'
                          ? 'bg-amber-500/10'
                          : alert.severity === 'low'
                          ? 'bg-blue-500/10'
                          : 'bg-slate-600/30'
                      }`}
                    >
                      {cfg.icon}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <Badge variant={cfg.variant}>{alert.severity.toUpperCase()}</Badge>
                        {alert.attack_type && (
                          <Badge variant="info">{alert.attack_type}</Badge>
                        )}
                        {alert.category === 'abnormal' && (
                          <Badge variant="danger">Abnormal</Badge>
                        )}
                        {alert.threat_intelligence_score != null && (
                          <Badge
                            variant={
                              alert.threat_intelligence_score >= 80
                                ? 'danger'
                                : alert.threat_intelligence_score >= 50
                                ? 'warning'
                                : 'success'
                            }
                          >
                            <ShieldCheck size={12} className="mr-1" />
                            Threat Intel: {alert.threat_intelligence_score}
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-slate-200">{alert.message}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                        {alert.app_name && (
                          <span className="flex items-center gap-1">
                            <AppWindow size={12} />
                            {alert.app_name}
                          </span>
                        )}
                        {alert.endpoint_name && (
                          <span className="flex items-center gap-1">
                            <Server size={12} />
                            {alert.endpoint_name}
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock size={12} />
                          {new Date(alert.timestamp).toLocaleString()}
                        </span>
                        {alert.confidence != null && (
                          <span className="flex items-center gap-1">
                            <Globe size={12} />
                            {Math.round(alert.confidence * 100)}% confidence
                          </span>
                        )}
                        {alert.feedback_action && (
                          <span className="flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 size={12} />
                            Action: {alert.feedback_action.replace('_', ' ')}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Expand chevron */}
                    <div className="shrink-0 text-slate-500">
                      {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                    </div>
                  </div>

                  {/* Expanded content */}
                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t border-slate-700/30">
                      <div className="mb-4">
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                          Response Actions
                        </h4>
                        <div className="flex flex-wrap gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            icon={<CheckCircle2 size={13} />}
                            loading={actionLoadingId === alert.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              runAction(
                                alert.id,
                                () => alertService.markFalsePositive(alert.id),
                                'Alert marked as false positive and added to feedback dataset.'
                              );
                            }}
                          >
                            Mark False Positive
                          </Button>

                          <Button
                            size="sm"
                            variant="secondary"
                            icon={<Shield size={13} />}
                            loading={actionLoadingId === alert.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              runAction(
                                alert.id,
                                () => alertService.whitelist(alert.id, { target_type: 'ip' }),
                                'IP whitelist rule created.'
                              );
                            }}
                          >
                            Whitelist IP
                          </Button>

                          <Button
                            size="sm"
                            variant="secondary"
                            icon={<AppWindow size={13} />}
                            loading={actionLoadingId === alert.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              runAction(
                                alert.id,
                                () => alertService.whitelist(alert.id, { target_type: 'app' }),
                                'App whitelist rule created.'
                              );
                            }}
                          >
                            Whitelist App
                          </Button>

                          <Button
                            size="sm"
                            variant="ghost"
                            icon={<VolumeX size={13} />}
                            loading={actionLoadingId === alert.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              runAction(
                                alert.id,
                                () => alertService.silenceRule(alert.id, { policy_id: policySilenceByAlert[alert.id] || undefined }),
                                'Silence rule enabled for similar alerts.'
                              );
                            }}
                          >
                            Silence Rule
                          </Button>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
                          <input
                            className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200"
                            placeholder="Whitelist domain (optional), e.g. api.example.com"
                            value={domainWhitelistByAlert[alert.id] || ''}
                            onChange={(e) =>
                              setDomainWhitelistByAlert((prev) => ({
                                ...prev,
                                [alert.id]: e.target.value,
                              }))
                            }
                          />
                          <Button
                            size="sm"
                            variant="secondary"
                            icon={<Ban size={13} />}
                            loading={actionLoadingId === alert.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              runAction(
                                alert.id,
                                () =>
                                  alertService.whitelist(alert.id, {
                                    target_type: 'domain',
                                    target_value: (domainWhitelistByAlert[alert.id] || '').trim(),
                                  }),
                                'Domain whitelist rule created.'
                              );
                            }}
                          >
                            Whitelist Domain
                          </Button>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
                          <input
                            className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200"
                            placeholder="Policy ID to disable (optional)"
                            value={policySilenceByAlert[alert.id] || ''}
                            onChange={(e) =>
                              setPolicySilenceByAlert((prev) => ({
                                ...prev,
                                [alert.id]: e.target.value,
                              }))
                            }
                          />
                          <p className="text-xs text-slate-500 self-center">
                            If set, this policy is deactivated in addition to creating a silence rule.
                          </p>
                        </div>
                      </div>

                      {(alert.explanation_features ?? []).length > 0 && (
                        <div className="mb-4">
                          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                            <List size={12} />
                            ML Explanation
                          </h4>
                          <ul className="list-disc list-inside space-y-1">
                            {alert.explanation_features?.map((feature, idx) => (
                              <li key={idx} className="text-xs text-slate-300">{feature}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                        Flow Context
                      </h4>
                      <FlowContextDetail context={(alert as unknown as { context?: FlowContext }).context} />
                    </div>
                  )}
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default Alerts;
