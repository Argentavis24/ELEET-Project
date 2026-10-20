import React, { useState } from 'react';
import { 
  Download, Filter, Search, ArrowUpDown, ChevronLeft, 
  ChevronRight, RefreshCw, Shield, AlertTriangle 
} from 'lucide-react';
import type { NetworkFlow } from '../types';
import { api } from '../services/api';

interface FlowTableProps {
  flows: NetworkFlow[];
  totalFlows: number;
  currentPage: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onFilterChange: (filters: any) => void;
  isLoading: boolean;
  onRefresh: () => void;
}

export const FlowTable: React.FC<FlowTableProps> = ({
  flows,
  totalFlows,
  currentPage,
  pageSize,
  onPageChange,
  onFilterChange,
  isLoading,
  onRefresh
}) => {
  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('');
  const [classification, setClassification] = useState('');
  const [minRisk, setMinRisk] = useState<number>(0);
  const [port, setPort] = useState<string>('');
  const [showFilters, setShowFilters] = useState(false);

  const handleApplyFilter = () => {
    onFilterChange({
      search: search || undefined,
      protocol: protocol || undefined,
      classification: classification || undefined,
      min_risk: minRisk > 0 ? minRisk : undefined,
      port: port ? parseInt(port) : undefined,
    });
  };

  const handleReset = () => {
    setSearch('');
    setProtocol('');
    setClassification('');
    setMinRisk(0);
    setPort('');
    onFilterChange({});
  };

  const handleExportCSV = () => {
    const exportUrl = api.getFlowsExportUrl({
      protocol: protocol || undefined,
      classification: classification || undefined,
      min_risk: minRisk > 0 ? minRisk : undefined,
      port: port ? parseInt(port) : undefined,
      limit: 2000
    });
    window.open(exportUrl, '_blank');
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const classificationStyle = (cls: string) => {
    if (cls === 'Normal') return 'bg-emerald-950/60 text-emerald-400 border-emerald-800';
    if (cls.includes('Blocked')) return 'bg-purple-950/60 text-purple-400 border-purple-800';
    if (cls.includes('DDoS') || cls.includes('Blacklist') || cls.includes('ARP')) {
      return 'bg-rose-950/60 text-rose-400 border-rose-800';
    }
    return 'bg-amber-950/60 text-amber-400 border-amber-800';
  };

  const totalPages = Math.ceil(totalFlows / pageSize);

  return (
    <div className="space-y-4">
      {/* Top Filter and Actions Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm space-y-3">
        <div className="flex flex-col md:flex-row items-center justify-between gap-3">
          {/* Main search bar */}
          <div className="relative w-full md:w-96">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleApplyFilter()}
              placeholder="Search by IP, classification, or reason..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 w-full md:w-auto justify-end">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`px-3 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors ${
                showFilters || protocol || classification || minRisk > 0 || port
                  ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300'
                  : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
              }`}
            >
              <Filter className="w-3.5 h-3.5" />
              Advanced Filters
            </button>

            <button
              onClick={handleExportCSV}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              Export CSV
            </button>

            <button
              onClick={onRefresh}
              disabled={isLoading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Refresh flows"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Collapsible Advanced Filters Drawer */}
        {showFilters && (
          <div className="pt-3 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Protocol</label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
              >
                <option value="">All Protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ARP">ARP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Port</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="e.g. 80, 443, 22"
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Classification</label>
              <select
                value={classification}
                onChange={(e) => setClassification(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
              >
                <option value="">All Types</option>
                <option value="Normal">Normal</option>
                <option value="Port Scan">Port Scan</option>
                <option value="Brute Force">Brute Force</option>
                <option value="DDoS Flood">DDoS Flood</option>
                <option value="Suspicious Outbound">Suspicious Outbound</option>
                <option value="ARP Spoofing">ARP Spoofing</option>
                <option value="Blacklisted IP">Blacklisted IP</option>
                <option value="Blocked (Quarantine)">Blocked (Quarantine)</option>
                <option value="ML Anomaly">ML Anomaly</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">
                Min Threat Score: {(minRisk * 100).toFixed(0)}%
              </label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={minRisk}
                onChange={(e) => setMinRisk(parseFloat(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer"
              />
            </div>

            <div className="sm:col-span-2 md:col-span-4 flex justify-end gap-2 pt-1">
              <button
                onClick={handleReset}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs"
              >
                Reset Filters
              </button>
              <button
                onClick={handleApplyFilter}
                className="px-4 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs"
              >
                Apply Filters
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Main Flow Data Table */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-3">Timestamp</th>
                <th className="py-3 px-3">Source Host:Port</th>
                <th className="py-3 px-3">Target Host:Port</th>
                <th className="py-3 px-2">Proto</th>
                <th className="py-3 px-2">Packets</th>
                <th className="py-3 px-2">Bytes</th>
                <th className="py-3 px-2">Duration</th>
                <th className="py-3 px-3">Classification</th>
                <th className="py-3 px-3">Risk Score</th>
                <th className="py-3 px-3">Reason / Vector</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-500">
                    No network flows found matching the criteria.
                  </td>
                </tr>
              ) : (
                flows.map((flow) => {
                  const riskPct = Math.round(flow.risk_score * 100);
                  const isHighRisk = flow.risk_score >= 0.70;
                  const isMedRisk = flow.risk_score >= 0.40 && flow.risk_score < 0.70;

                  return (
                    <tr 
                      key={flow.id} 
                      className={`hover:bg-slate-800/40 transition-colors ${isHighRisk ? 'bg-rose-950/10' : ''}`}
                    >
                      <td className="py-2.5 px-3 whitespace-nowrap text-slate-400">
                        {new Date(flow.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 font-semibold text-white">
                        {flow.src_ip}:{flow.src_port}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {flow.dst_ip}:{flow.dst_port}
                      </td>
                      <td className="py-2.5 px-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 border border-slate-700">
                          {flow.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-2 text-slate-400">
                        {flow.packet_count}
                      </td>
                      <td className="py-2.5 px-2 text-slate-400 whitespace-nowrap">
                        {formatBytes(flow.byte_count)}
                      </td>
                      <td className="py-2.5 px-2 text-slate-400 whitespace-nowrap">
                        {flow.duration.toFixed(2)}s
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${classificationStyle(flow.classification)}`}>
                          {flow.classification}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5 w-24">
                          <div className="w-14 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                isHighRisk ? 'bg-rose-500' : isMedRisk ? 'bg-amber-400' : 'bg-emerald-400'
                              }`}
                              style={{ width: `${riskPct}%` }}
                            />
                          </div>
                          <span className={`font-bold ${
                            isHighRisk ? 'text-rose-400' : isMedRisk ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {riskPct}%
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px] truncate max-w-xs" title={flow.alert_reason || ''}>
                        {flow.alert_reason || '-'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="px-4 py-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <div>
            Showing flows {flows.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} to{' '}
            {Math.min(currentPage * pageSize, totalFlows)} of {totalFlows.toLocaleString()} total
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage <= 1 || isLoading}
              className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 disabled:opacity-40 hover:bg-slate-800 transition-colors flex items-center gap-1"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              Prev
            </button>
            <span className="text-white font-bold">
              Page {currentPage} of {Math.max(totalPages, 1)}
            </span>
            <button
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage >= totalPages || isLoading}
              className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 disabled:opacity-40 hover:bg-slate-800 transition-colors flex items-center gap-1"
            >
              Next
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
