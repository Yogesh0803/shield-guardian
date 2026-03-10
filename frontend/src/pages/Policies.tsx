import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Globe,
  Network,
  Clock,
  FileText,
  ShieldOff,
  ShieldCheck,
} from 'lucide-react';
import { Card, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import { Skeleton } from '../components/ui/Skeleton';
import { policyService } from '../services/policy.service';
import type { Policy, PolicyConditions } from '../types';

function summarizeConditions(conditions: PolicyConditions | null | undefined): string {
  if (!conditions) return 'No conditions defined';
  const parts: string[] = [];
  if (conditions.domains?.length) parts.push(`${conditions.domains.length} domain(s)`);
  if (conditions.ips?.length) parts.push(`${conditions.ips.length} IP(s)`);
  if (conditions.ports?.length) parts.push(`${conditions.ports.length} port(s)`);
  if (conditions.app_names?.length) parts.push(`${conditions.app_names.length} app(s)`);
  if (conditions.geo_countries?.length) parts.push(`${conditions.geo_countries.length} country(s)`);
  if (conditions.time_range) parts.push('time-based');
  if (conditions.anomaly_threshold != null) parts.push(`anomaly > ${conditions.anomaly_threshold}`);
  if (conditions.rate_limit != null) parts.push(`rate limit: ${conditions.rate_limit}/${conditions.rate_limit_window ?? 60}s`);
  if (conditions.attack_types?.length) parts.push(`${conditions.attack_types.length} attack type(s)`);
  if (conditions.protocols?.length) parts.push(`protocols: ${conditions.protocols.join(', ')}`);
  if (conditions.isolation_scope) parts.push(`isolate: ${conditions.isolation_scope}`);
  if (conditions.monitor_mode) parts.push(`monitor: ${conditions.monitor_mode}`);
  if (conditions.severity) parts.push(`severity: ${conditions.severity}`);
  if (conditions.auto_expire) parts.push(`expires in ${conditions.auto_expire}s`);
  return parts.length ? parts.join(' | ') : 'No conditions defined';
}

const Policies: React.FC = () => {
  const navigate = useNavigate();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteModal, setDeleteModal] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);

  useEffect(() => {
    fetchPolicies();
  }, []);

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await policyService.getAll();
      setPolicies(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to fetch policies';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteModal) return;
    try {
      setDeleting(true);
      await policyService.delete(deleteModal);
      setPolicies((prev) => prev.filter((p) => p.id !== deleteModal));
      setDeleteModal(null);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete policy';
      setError(message);
    } finally {
      setDeleting(false);
    }
  };

  const handleToggle = async (id: string) => {
    try {
      setTogglingId(id);
      const updated = await policyService.toggle(id);
      setPolicies((prev) => prev.map((p) => (p.id === id ? updated : p)));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to toggle policy';
      setError(message);
    } finally {
      setTogglingId(null);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 p-6 lg:p-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <Shield className="text-blue-500" size={28} />
            Policy Management
          </h1>
          <p className="text-slate-400 mt-1">Configure firewall rules and access controls</p>
        </div>
        <Button
          variant="primary"
          icon={<Plus size={16} />}
          onClick={() => navigate('/policies/new')}
        >
          Create Policy
        </Button>
      </div>

      {/* Error */}
      {error && (
        <Card className="mb-6 border-red-500/30">
          <CardContent>
            <p className="text-red-400 text-sm">{error}</p>
          </CardContent>
        </Card>
      )}

      {/* Loading */}
      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="space-y-3">
                <Skeleton className="h-5 w-40" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-3/4" />
                <div className="flex gap-2">
                  <Skeleton className="h-6 w-16" />
                  <Skeleton className="h-6 w-16" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && policies.length === 0 && (
        <Card>
          <CardContent className="py-20 text-center">
            <ShieldOff className="mx-auto text-slate-500 mb-4" size={56} />
            <h3 className="text-xl font-semibold text-slate-300 mb-2">No Policies Yet</h3>
            <p className="text-slate-500 text-sm mb-6 max-w-md mx-auto">
              Policies define how your firewall handles traffic. Create your first policy to start
              protecting your endpoints.
            </p>
            <Button
              variant="primary"
              icon={<Plus size={16} />}
              onClick={() => navigate('/policies/new')}
            >
              Create Your First Policy
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Policy Cards */}
      {!loading && policies.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {policies.map((policy) => (
            <Card key={policy.id} hover>
              <CardContent className="space-y-4">
                {/* Title & Purpose */}
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <h3 className="text-base font-semibold text-slate-100 truncate">
                      {policy.name}
                    </h3>
                    <p className="text-sm text-slate-400 mt-1 line-clamp-2">
                      {policy.description || 'No description'}
                    </p>
                  </div>
                  <Badge variant={
                    policy.purpose === 'block' ? 'danger' :
                    policy.purpose === 'unblock' ? 'success' :
                    policy.purpose === 'isolate' ? 'danger' :
                    policy.purpose === 'alert' ? 'warning' : 'info'
                  } className="ml-3 shrink-0">
                    {policy.purpose === 'block' ? (
                      <span className="flex items-center gap-1">
                        <ShieldOff size={12} /> Block
                      </span>
                    ) : policy.purpose === 'unblock' ? (
                      <span className="flex items-center gap-1">
                        <ShieldCheck size={12} /> Allow
                      </span>
                    ) : (
                      <span className="flex items-center gap-1">
                        <Shield size={12} /> {(policy.purpose || 'Policy').replace('_', ' ')}
                      </span>
                    )}
                  </Badge>
                </div>

                {/* Conditions Summary */}
                <div className="p-3 rounded-md bg-slate-700/30 border border-slate-700/30">
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                    <FileText size={12} />
                    Conditions
                  </p>
                  <p className="text-xs text-slate-300">
                    {summarizeConditions(policy.conditions)}
                  </p>
                </div>

                {/* Condition tags */}
                <div className="flex flex-wrap gap-1.5">
                  {policy.conditions?.domains?.slice(0, 3).map((d) => (
                    <Badge key={d} variant="info">
                      <Globe size={10} className="mr-1" />
                      {d}
                    </Badge>
                  ))}
                  {policy.conditions?.ips?.slice(0, 2).map((ip) => (
                    <Badge key={ip} variant="default">
                      <Network size={10} className="mr-1" />
                      {ip}
                    </Badge>
                  ))}
                  {policy.conditions?.time_range && (
                    <Badge variant="warning">
                      <Clock size={10} className="mr-1" />
                      {policy.conditions.time_range.start} - {policy.conditions.time_range.end}
                    </Badge>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between pt-2 border-t border-slate-700/30">
                  <button
                    onClick={() => handleToggle(policy.id)}
                    disabled={togglingId === policy.id}
                    className="flex items-center gap-2 text-sm transition-colors duration-200 cursor-pointer disabled:opacity-50"
                  >
                    {policy.is_active ? (
                      <>
                        <ToggleRight size={22} className="text-blue-400" />
                        <span className="text-blue-400">Active</span>
                      </>
                    ) : (
                      <>
                        <ToggleLeft size={22} className="text-slate-500" />
                        <span className="text-slate-500">Inactive</span>
                      </>
                    )}
                  </button>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={<Trash2 size={14} />}
                    onClick={() => setDeleteModal(policy.id)}
                    className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                  >
                    Delete
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete Policy"
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-slate-300 text-sm">
            Are you sure you want to delete this policy? This action cannot be undone and may leave
            endpoints unprotected.
          </p>
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleDelete} loading={deleting}>
              Delete Policy
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default Policies;
