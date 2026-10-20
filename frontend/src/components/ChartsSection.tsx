import React from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  PieChart, Pie, Cell, BarChart, Bar, CartesianGrid, Legend 
} from 'recharts';
import { Shield, Ban, CheckCircle2, AlertTriangle } from 'lucide-react';
import type { DashboardCharts } from '../types';

interface ChartsSectionProps {
  charts: DashboardCharts | null;
  onQuarantineIP: (ip: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#f43f5e', // rose-500
  High: '#f97316',     // orange-500
  Medium: '#eab308',   // yellow-500
  Low: '#06b6d4',      // cyan-500
};

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#06b6d4',      // cyan
  UDP: '#8b5cf6',      // purple
  ARP: '#f59e0b',      // amber
  ICMP: '#10b981',     // emerald
  OTHER: '#64748b'     // slate
};

export const ChartsSection: React.FC<ChartsSectionProps> = ({ charts, onQuarantineIP }) => {
  if (!charts) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 my-6">
        <div className="h-64 bg-slate-900/40 rounded-xl border border-slate-800 animate-pulse flex items-center justify-center text-slate-500 text-sm">
          Loading threat intelligence analytics...
        </div>
        <div className="h-64 bg-slate-900/40 rounded-xl border border-slate-800 animate-pulse flex items-center justify-center text-slate-500 text-sm">
          Loading protocol breakdown...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 my-6">
      {/* Top Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 1. Traffic & Threats Over Time (2 cols) */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                Network Throughput & Threat Activity Over Time
              </h3>
              <p className="text-xs text-slate-400">
                Real-time correlation of flow byte volume vs. detected threats
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                Bytes
              </span>
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
                Threat Spikes
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={charts.traffic_over_time} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="bytesGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Area type="monotone" dataKey="bytes" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#bytesGradient)" name="Bytes Transferred" />
                <Area type="monotone" dataKey="threats" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#threatsGradient)" name="Threat Events" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* 2. Protocol Distribution (1 col) */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
              Protocol Distribution
            </h3>
            <p className="text-xs text-slate-400 mb-2">
              L4 protocol breakdown in active buffer
            </p>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={charts.protocol_distribution}
                  dataKey="count"
                  nameKey="protocol"
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                >
                  {charts.protocol_distribution.map((entry) => (
                    <Cell 
                      key={entry.protocol} 
                      fill={PROTOCOL_COLORS[entry.protocol.toUpperCase()] || PROTOCOL_COLORS.OTHER} 
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Legend 
                  verticalAlign="bottom" 
                  height={36} 
                  formatter={(value) => <span className="text-xs text-slate-300 font-mono">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Grid: Severity Breakdown & Top Threat Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alert Severity Bar Chart */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
          <div className="mb-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
              Alerts by Severity Level
            </h3>
            <p className="text-xs text-slate-400">
              Triage priority distribution across active detections
            </p>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={charts.alert_severity} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="severity" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {charts.alert_severity.map((entry) => (
                    <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] || '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Source IPs / Threat Actors (2 cols) */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                Top Communicating & High-Risk Source IPs
              </h3>
              <p className="text-xs text-slate-400">
                Heuristic & ML risk rankings with immediate quarantine defense
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2.5 py-1 rounded border border-cyan-800">
              Active Monitoring
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Source Host / IP</th>
                  <th className="py-2.5 px-3">Flows</th>
                  <th className="py-2.5 px-3">Traffic Vol</th>
                  <th className="py-2.5 px-3">Max Threat Score</th>
                  <th className="py-2.5 px-3">Defense Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {charts.top_source_ips.map((item) => (
                  <tr key={item.ip} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-3 font-semibold text-white">
                      {item.ip}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {item.flows.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {(item.bytes / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                          <div 
                            className={`h-full rounded-full ${
                              item.max_risk >= 0.8 ? 'bg-rose-500' : (item.max_risk >= 0.5 ? 'bg-amber-400' : 'bg-emerald-400')
                            }`}
                            style={{ width: `${Math.round(item.max_risk * 100)}%` }}
                          />
                        </div>
                        <span className={`font-bold ${item.max_risk >= 0.8 ? 'text-rose-400' : (item.max_risk >= 0.5 ? 'text-amber-400' : 'text-emerald-400')}`}>
                          {(item.max_risk * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      {item.is_blocked ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800">
                          <Ban className="w-3 h-3" />
                          QUARANTINED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                          <CheckCircle2 className="w-3 h-3" />
                          CLEAN / ACTIVE
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      {!item.is_blocked && (
                        <button
                          onClick={() => onQuarantineIP(item.ip)}
                          className="px-2 py-1 text-[11px] rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 transition-colors inline-flex items-center gap-1 font-sans"
                        >
                          <Shield className="w-3 h-3" />
                          Quarantine
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
