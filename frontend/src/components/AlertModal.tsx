import React, { useState } from 'react';
import { 
  X, ShieldAlert, Shield, CheckCircle2, Clock, 
  Terminal, AlertTriangle, FileText, Send 
} from 'lucide-react';
import type { Alert } from '../types';

interface AlertModalProps {
  alert: Alert | null;
  onClose: () => void;
  onUpdateStatus: (alertId: number, status: string, notes?: string) => Promise<void>;
  onQuarantine: (alertId: number) => Promise<void>;
}

export const AlertModal: React.FC<AlertModalProps> = ({
  alert,
  onClose,
  onUpdateStatus,
  onQuarantine
}) => {
  if (!alert) return null;

  const [status, setStatus] = useState<string>(alert.status);
  const [notes, setNotes] = useState<string>(alert.notes || '');
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [isQuarantining, setIsQuarantining] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  let formattedEvidence: any = null;
  try {
    formattedEvidence = JSON.parse(alert.evidence);
  } catch {
    formattedEvidence = alert.evidence;
  }

  const handleSaveNotes = async () => {
    setIsSaving(true);
    setActionMessage(null);
    try {
      await onUpdateStatus(alert.id, status, notes);
      setActionMessage('Status and notes updated successfully.');
    } catch (e: any) {
      setActionMessage(`Error: ${e.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleQuarantineClick = async () => {
    setIsQuarantining(true);
    setActionMessage(null);
    try {
      await onQuarantine(alert.id);
      setStatus('INVESTIGATING');
      setActionMessage(`IP ${alert.src_ip} quarantined successfully.`);
    } catch (e: any) {
      setActionMessage(`Quarantine error: ${e.message}`);
    } finally {
      setIsQuarantining(false);
    }
  };

  const severityBadge = {
    Critical: 'bg-rose-500/20 text-rose-400 border-rose-500/40',
    High: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    Low: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
  }[alert.severity] || 'bg-slate-800 text-slate-300';

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="relative w-full max-w-3xl rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-white tracking-wide">
                  Alert #{alert.id}: {alert.rule_name}
                </span>
                <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${severityBadge}`}>
                  {alert.severity}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Detected: {new Date(alert.timestamp).toLocaleString()}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto text-sm">
          {/* Action notification */}
          {actionMessage && (
            <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-300 text-xs font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              {actionMessage}
            </div>
          )}

          {/* Attacker vs Victim Card */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-xs font-semibold text-rose-400 uppercase tracking-wider block mb-1">
                Source / Threat Actor
              </span>
              <div className="font-mono text-base font-bold text-white">
                {alert.src_ip}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                Port: {alert.src_port || 'N/A'} | Protocol: {alert.protocol || 'TCP'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider block mb-1">
                Target / Destination Host
              </span>
              <div className="font-mono text-base font-bold text-white">
                {alert.dst_ip}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                Port: {alert.dst_port || 'N/A'}
              </div>
            </div>
          </div>

          {/* Explanation */}
          <div>
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Detection Explanation
            </h4>
            <p className="text-slate-200 bg-slate-950/40 p-3 rounded-lg border border-slate-800/80 leading-relaxed font-sans">
              {alert.explanation}
            </p>
          </div>

          {/* Recommended Response */}
          <div>
            <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5" />
              Recommended SOC Response
            </h4>
            <p className="text-emerald-200/90 bg-emerald-950/20 p-3 rounded-lg border border-emerald-900/40 leading-relaxed font-sans text-xs">
              {alert.recommended_action}
            </p>
          </div>

          {/* Raw Evidence JSON Viewer */}
          <div>
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              Raw Flow Evidence & Metrics
            </h4>
            <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto">
              {typeof formattedEvidence === 'object'
                ? JSON.stringify(formattedEvidence, null, 2)
                : String(formattedEvidence)}
            </pre>
          </div>

          {/* Analyst Triage & Actions */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              Analyst Investigation & Triage Workflow
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Alert Lifecycle Status
                </label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="NEW">NEW</option>
                  <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="button"
                  onClick={handleQuarantineClick}
                  disabled={isQuarantining}
                  className="w-full py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-2"
                >
                  <Shield className="w-4 h-4" />
                  {isQuarantining ? 'Quarantining...' : `Quarantine IP ${alert.src_ip}`}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">
                Analyst Investigation Notes
              </label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                placeholder="Document containment steps, root cause analysis, or verification findings..."
                className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={handleSaveNotes}
                disabled={isSaving}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors flex items-center gap-1.5"
              >
                <Send className="w-3.5 h-3.5" />
                {isSaving ? 'Saving...' : 'Save Triage Notes & Status'}
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-950 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
