import React, { useState } from 'react';
import { Ban, ShieldCheck, Plus, RefreshCw, AlertCircle, CheckCircle2 } from 'lucide-react';
import type { QuarantinedIP } from '../types';

interface QuarantineModalProps {
  blockedIps: QuarantinedIP[];
  onUnblock: (ip: string) => Promise<void>;
  onBlock: (ip: string, reason: string) => Promise<void>;
  onRefresh: () => void;
  isLoading: boolean;
}

export const QuarantineModal: React.FC<QuarantineModalProps> = ({
  blockedIps,
  onUnblock,
  onBlock,
  onRefresh,
  isLoading
}) => {
  const [newIp, setNewIp] = useState('');
  const [newReason, setNewReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const handleManualBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIp.trim()) return;
    setIsSubmitting(true);
    setMessage(null);
    try {
      await onBlock(newIp.trim(), newReason.trim() || 'Manual SOC quarantine rule');
      setNewIp('');
      setNewReason('');
      setMessage(`Host ${newIp} successfully quarantined.`);
    } catch (err: any) {
      setMessage(`Error: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUnblockClick = async (ip: string) => {
    try {
      await onUnblock(ip);
      setMessage(`IP ${ip} released from active quarantine.`);
    } catch (err: any) {
      setMessage(`Error releasing IP: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Manual Quarantine Form */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
              <Ban className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide">
                Active Threat Defense & IP Quarantine
              </h2>
              <p className="text-xs text-slate-400">
                Any subsequent flows to or from quarantined IPs are dropped immediately at ingress.
              </p>
            </div>
          </div>
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>

        {message && (
          <div className="mb-4 p-3 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-300 text-xs font-mono flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            {message}
          </div>
        )}

        {/* Manual block input */}
        <form onSubmit={handleManualBlock} className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-4">
            <input
              type="text"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              placeholder="IP Address (e.g. 198.51.100.99)"
              required
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-rose-500"
            />
          </div>
          <div className="md:col-span-6">
            <input
              type="text"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              placeholder="Reason (e.g. Confirmed C2 beacon / lateral movement)"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 font-sans focus:outline-none focus:border-rose-500"
            />
          </div>
          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-medium text-xs transition-colors flex items-center justify-center gap-1.5 font-sans"
            >
              <Plus className="w-4 h-4" />
              {isSubmitting ? 'Blocking...' : 'Block IP'}
            </button>
          </div>
        </form>
      </div>

      {/* Quarantined IP List Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Quarantined IP</th>
                <th className="py-3 px-4">Reason / Threat Vector</th>
                <th className="py-3 px-4">Blocked Timestamp</th>
                <th className="py-3 px-4">Enforced By</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {blockedIps.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-40 text-emerald-400" />
                    No active quarantined IPs. Perimeter is clean.
                  </td>
                </tr>
              ) : (
                blockedIps.map((b) => (
                  <tr key={b.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-rose-400">
                      {b.ip_address}
                    </td>
                    <td className="py-3 px-4 text-slate-300 font-sans text-xs">
                      {b.reason}
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(b.blocked_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {b.blocked_by}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">
                        ACTIVE QUARANTINE
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleUnblockClick(b.ip_address)}
                        className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-sans transition-colors inline-flex items-center gap-1"
                      >
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        Release / Unblock
                      </button>
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
