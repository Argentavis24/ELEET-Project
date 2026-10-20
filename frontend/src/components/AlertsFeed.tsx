import React, { useState } from 'react';
import { 
  ShieldAlert, Shield, Filter, Search, Eye, 
  Clock, CheckCircle2, AlertTriangle, AlertCircle, RefreshCw 
} from 'lucide-react';
import type { Alert } from '../types';

interface AlertsFeedProps {
  alerts: Alert[];
  onSelectAlert: (alert: Alert) => void;
  onQuarantineIP: (ip: string) => void;
  onRefresh: () => void;
  isLoading: boolean;
}

export const AlertsFeed: React.FC<AlertsFeedProps> = ({
  alerts,
  onSelectAlert,
  onQuarantineIP,
  onRefresh,
  isLoading
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== 'ALL' && alert.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && alert.status !== statusFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchSrc = alert.src_ip.toLowerCase().includes(q);
      const matchDst = alert.dst_ip.toLowerCase().includes(q);
      const matchRule = alert.rule_name.toLowerCase().includes(q);
      const matchExpl = alert.explanation.toLowerCase().includes(q);
      if (!matchSrc && !matchDst && !matchRule && !matchExpl) return false;
    }
    return true;
  });

  const severityBadge = (severity: string) => {
    const map: Record<string, string> = {
      Critical: 'bg-rose-500/20 text-rose-400 border-rose-500/40',
      High: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
      Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
      Low: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
    };
    return map[severity] || 'bg-slate-800 text-slate-300';
  };

  const statusBadge = (status: string) => {
    const map: Record<string, string> = {
      NEW: 'bg-rose-950 text-rose-300 border-rose-800',
      ACKNOWLEDGED: 'bg-amber-950 text-amber-300 border-amber-800',
      INVESTIGATING: 'bg-blue-950 text-blue-300 border-blue-800',
      RESOLVED: 'bg-emerald-950 text-emerald-300 border-emerald-800',
      FALSE_POSITIVE: 'bg-slate-800 text-slate-400 border-slate-700',
    };
    return map[status] || 'bg-slate-800 text-slate-400';
  };

  return (
    <div className="space-y-4">
      {/* Filters & Header Bar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP, rule, or explanation..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Severity selector */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            {['ALL', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors ${
                  severityFilter === sev
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Status selector */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
          </select>

          {/* Refresh */}
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Refresh alerts"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Rule / Detection</th>
                <th className="py-3 px-4">Threat Source IP</th>
                <th className="py-3 px-4">Target Destination</th>
                <th className="py-3 px-4">Detected Timestamp</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <Shield className="w-8 h-8 mx-auto mb-2 opacity-40 text-slate-400" />
                    No security alerts matching the current criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr 
                    key={alert.id}
                    className="hover:bg-slate-800/50 transition-colors group cursor-pointer"
                    onClick={() => onSelectAlert(alert)}
                  >
                    <td className="py-3 px-4">
                      <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${severityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-sans font-semibold text-white group-hover:text-cyan-400 transition-colors">
                        {alert.rule_name}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate max-w-xs font-sans">
                        {alert.explanation}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-rose-400 font-bold">
                      {alert.src_ip}
                      {alert.src_port ? `:${alert.src_port}` : ''}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {alert.dst_ip}
                      {alert.dst_port ? `:${alert.dst_port}` : ''}
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${statusBadge(alert.status)}`}>
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onSelectAlert(alert)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-sans text-xs transition-colors inline-flex items-center gap-1"
                        >
                          <Eye className="w-3.5 h-3.5 text-cyan-400" />
                          Investigate
                        </button>
                        <button
                          onClick={() => onQuarantineIP(alert.src_ip)}
                          className="px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 font-sans text-xs transition-colors inline-flex items-center gap-1"
                        >
                          <Shield className="w-3.5 h-3.5 text-rose-400" />
                          Quarantine
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
