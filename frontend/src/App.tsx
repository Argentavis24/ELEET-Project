import React, { useState, useEffect, useCallback } from 'react';
import { 
  ShieldAlert, Activity, Radio, Ban, Cpu, Shield, 
  AlertTriangle, Gauge, Wifi, Zap, CheckCircle2 
} from 'lucide-react';
import type { 
  NetworkFlow, Alert, DashboardMetrics, DashboardCharts, 
  QuarantinedIP, SimulationStatus, User 
} from './types';
import { api } from './services/api';
import { realtimeSocket } from './services/websocket';
import { Navbar } from './components/Navbar';
import { MetricCard } from './components/MetricCard';
import { ChartsSection } from './components/ChartsSection';
import { FlowTable } from './components/FlowTable';
import { AlertsFeed } from './components/AlertsFeed';
import { AlertModal } from './components/AlertModal';
import { QuarantineModal } from './components/QuarantineModal';
import { SimulatorDrawer } from './components/SimulatorDrawer';
import { LoginModal } from './components/LoginModal';
import { DatabaseScanner } from './components/DatabaseScanner';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<'dashboard' | 'flows' | 'alerts' | 'quarantine' | 'simulation' | 'dbms'>('dashboard');
  
  // Data states
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [charts, setCharts] = useState<DashboardCharts | null>(null);
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [totalFlows, setTotalFlows] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 50;
  const [flowFilters, setFlowFilters] = useState<any>({});

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  
  const [blockedIps, setBlockedIps] = useState<QuarantinedIP[]>([]);
  const [simulationStatus, setSimulationStatus] = useState<SimulationStatus | null>(null);
  
  // Auth state
  const [user, setUser] = useState<User | null>(null);
  const [isLoginOpen, setIsLoginOpen] = useState<boolean>(false);

  // WebSocket connection & live buffer control
  const [isWsConnected, setIsWsConnected] = useState<boolean>(false);
  const [isStreamPaused, setIsStreamPaused] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  // Toast / notification banner
  const [latestThreatToast, setLatestThreatToast] = useState<Alert | null>(null);

  // 1. Initial Load & Auth
  useEffect(() => {
    const initAuth = async () => {
      try {
        const currentUser = await api.getCurrentUser();
        setUser(currentUser);
      } catch {
        setUser(null);
      }
    };
    initAuth();
  }, []);

  // 2. Fetch Dashboard & Data
  const loadDashboardData = useCallback(async () => {
    try {
      const [m, c] = await Promise.all([api.getMetrics(), api.getCharts()]);
      setMetrics(m);
      setCharts(c);
    } catch (e) {
      console.error('Failed to load dashboard data', e);
    }
  }, []);

  const loadFlows = useCallback(async (page: number, filters: any) => {
    setIsLoading(true);
    try {
      const offset = (page - 1) * pageSize;
      const res = await api.getFlows({ limit: pageSize, offset, ...filters });
      setFlows(res.flows);
      setTotalFlows(res.total);
    } catch (e) {
      console.error('Failed to load flows', e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const loadAlerts = useCallback(async () => {
    try {
      const res = await api.getAlerts({ limit: 100 });
      setAlerts(res.alerts);
    } catch (e) {
      console.error('Failed to load alerts', e);
    }
  }, []);

  const loadQuarantine = useCallback(async () => {
    try {
      const res = await api.getQuarantineList();
      setBlockedIps(res.blocked_ips);
    } catch (e) {
      console.error('Failed to load quarantine list', e);
    }
  }, []);

  const loadSimulation = useCallback(async () => {
    try {
      const res = await api.getSimulationStatus();
      setSimulationStatus(res);
    } catch (e) {
      console.error('Failed to load simulation status', e);
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
    loadFlows(currentPage, flowFilters);
    loadAlerts();
    loadQuarantine();
    loadSimulation();

    // Periodic poll for charts and metrics to keep graphs alive
    const interval = setInterval(() => {
      loadDashboardData();
    }, 10000);
    return () => clearInterval(interval);
  }, [loadDashboardData, loadFlows, currentPage, flowFilters, loadAlerts, loadQuarantine, loadSimulation]);

  // 3. Connect Realtime WebSocket
  useEffect(() => {
    realtimeSocket.connect();

    const unsubStatus = realtimeSocket.onStatusChange((status) => {
      setIsWsConnected(status);
    });

    const unsubFlow = realtimeSocket.onFlow((newFlow) => {
      setFlows((prev) => [newFlow, ...prev.slice(0, pageSize - 1)]);
      setTotalFlows((prev) => prev + 1);
    });

    const unsubAlert = realtimeSocket.onAlert((newAlert) => {
      setAlerts((prev) => [newAlert, ...prev]);
      setMetrics((prev) => prev ? { ...prev, active_alerts: prev.active_alerts + 1 } : null);
      
      // Show notification banner
      setLatestThreatToast(newAlert);
      setTimeout(() => setLatestThreatToast(null), 6000);
    });

    return () => {
      unsubStatus();
      unsubFlow();
      unsubAlert();
      realtimeSocket.disconnect();
    };
  }, []);

  // Handle stream pause/resume
  const handleToggleStreamPause = (paused: boolean) => {
    setIsStreamPaused(paused);
    if (paused) {
      realtimeSocket.pause();
    } else {
      realtimeSocket.resume();
    }
  };

  // Actions
  const handleQuarantineIP = async (ip: string) => {
    await api.blockIP(ip, 'Analyst 1-click perimeter quarantine action');
    await loadQuarantine();
    await loadDashboardData();
  };

  const handleUnblockIP = async (ip: string) => {
    await api.unblockIP(ip);
    await loadQuarantine();
    await loadDashboardData();
  };

  const handleUpdateAlertStatus = async (alertId: number, status: string, notes?: string) => {
    const updated = await api.updateAlert(alertId, { status, notes });
    setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    setSelectedAlert(updated);
    await loadDashboardData();
  };

  const handleQuarantineFromAlert = async (alertId: number) => {
    await api.quarantineFromAlert(alertId);
    await loadQuarantine();
    await loadAlerts();
    await loadDashboardData();
  };

  const handleLogin = async (username: string, pass: string) => {
    const res = await api.login(username, pass);
    localStorage.setItem('nids_token', res.access_token);
    setUser(res.user);
  };

  const handleLogout = () => {
    localStorage.removeItem('nids_token');
    setUser(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        activeAlertsCount={metrics?.active_alerts || 0}
        isWsConnected={isWsConnected}
        isStreamPaused={isStreamPaused}
        setIsStreamPaused={handleToggleStreamPause}
        user={user}
        onOpenLogin={() => setIsLoginOpen(true)}
        onLogout={handleLogout}
        quarantinedCount={blockedIps.length}
      />

      {/* Realtime Threat Toast Notification */}
      {latestThreatToast && (
        <div 
          onClick={() => setSelectedAlert(latestThreatToast)}
          className="fixed bottom-5 right-5 z-50 p-4 rounded-xl bg-slate-900 border border-rose-500/50 shadow-2xl cursor-pointer max-w-md animate-slide-up flex items-start gap-3 backdrop-blur-md"
        >
          <div className="p-2 rounded-lg bg-rose-500/20 text-rose-400 shrink-0">
            <ShieldAlert className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-xs text-rose-400 uppercase tracking-wide">
                Active Threat Detected!
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded font-bold bg-rose-950 text-rose-300 border border-rose-800">
                {latestThreatToast.severity}
              </span>
            </div>
            <div className="text-sm font-semibold text-white mt-0.5">
              {latestThreatToast.rule_name}
            </div>
            <div className="text-xs text-slate-400 truncate max-w-xs font-mono mt-0.5">
              Src: {latestThreatToast.src_ip} &rarr; Dst: {latestThreatToast.dst_ip}
            </div>
          </div>
        </div>
      )}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Metric Cards Row (Always Visible on Dashboard) */}
        {currentTab === 'dashboard' && (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              <MetricCard
                title="Total Monitored Flows"
                value={metrics ? metrics.total_flows.toLocaleString() : '...'}
                subtitle="Aggregated traffic telemetry"
                icon={<Radio className="w-5 h-5" />}
                trend="+Live Stream"
                variant="cyan"
              />

              <MetricCard
                title="Active Security Alerts"
                value={metrics ? metrics.active_alerts : '...'}
                subtitle={`${metrics?.critical_alerts || 0} Critical Priority`}
                icon={<ShieldAlert className="w-5 h-5" />}
                badge={metrics?.active_alerts ? 'Action Needed' : 'Nominal'}
                variant="rose"
              />

              <MetricCard
                title="Active IP Quarantine"
                value={blockedIps.length}
                subtitle="Hosts blocked at perimeter"
                icon={<Ban className="w-5 h-5" />}
                badge="Enforced"
                variant="amber"
              />

              <MetricCard
                title="Real-Time Throughput"
                value={metrics ? `${metrics.throughput_kbps} Kbps` : '...'}
                subtitle={metrics ? `${metrics.packets_per_sec} packets/sec` : 'Measuring...'}
                icon={<Gauge className="w-5 h-5" />}
                trend="100% Ingested"
                variant="emerald"
              />
            </div>

            {/* Charts Section */}
            <ChartsSection
              charts={charts}
              onQuarantineIP={handleQuarantineIP}
            />

            {/* Quick Live Preview Table */}
            <div className="mt-8 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-cyan-400" />
                    Live Flow Ingestion Buffer
                  </h3>
                  <p className="text-xs text-slate-400">
                    Showing latest sub-second stream packets evaluated by NIDS engine
                  </p>
                </div>
                <button
                  onClick={() => setCurrentTab('flows')}
                  className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
                >
                  View Full Flow Explorer &rarr;
                </button>
              </div>

              <div className="rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm overflow-hidden">
                <div className="overflow-x-auto max-h-72">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider sticky top-0 border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Time</th>
                        <th className="py-2.5 px-3">Source IP</th>
                        <th className="py-2.5 px-3">Destination IP</th>
                        <th className="py-2.5 px-2">Proto</th>
                        <th className="py-2.5 px-2">Packets</th>
                        <th className="py-2.5 px-3">Classification</th>
                        <th className="py-2.5 px-3">Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {flows.slice(0, 10).map((flow) => (
                        <tr key={flow.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-2 px-3 text-slate-400">{new Date(flow.timestamp).toLocaleTimeString()}</td>
                          <td className="py-2 px-3 font-semibold text-white">{flow.src_ip}:{flow.src_port}</td>
                          <td className="py-2 px-3 text-slate-300">{flow.dst_ip}:{flow.dst_port}</td>
                          <td className="py-2 px-2 text-cyan-400">{flow.protocol}</td>
                          <td className="py-2 px-2 text-slate-400">{flow.packet_count}</td>
                          <td className="py-2 px-3 font-bold">{flow.classification}</td>
                          <td className="py-2 px-3">
                            <span className={`font-bold ${flow.risk_score >= 0.7 ? 'text-rose-400' : (flow.risk_score >= 0.4 ? 'text-amber-400' : 'text-emerald-400')}`}>
                              {(flow.risk_score * 100).toFixed(0)}%
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </>
        )}

        {/* Tab: Full Flow Table */}
        {currentTab === 'flows' && (
          <FlowTable
            flows={flows}
            totalFlows={totalFlows}
            currentPage={currentPage}
            pageSize={pageSize}
            onPageChange={(p) => setCurrentPage(p)}
            onFilterChange={(f) => {
              setFlowFilters(f);
              setCurrentPage(1);
            }}
            isLoading={isLoading}
            onRefresh={() => loadFlows(currentPage, flowFilters)}
          />
        )}

        {/* Tab: Security Alerts */}
        {currentTab === 'alerts' && (
          <AlertsFeed
            alerts={alerts}
            onSelectAlert={(alert) => setSelectedAlert(alert)}
            onQuarantineIP={handleQuarantineIP}
            onRefresh={loadAlerts}
            isLoading={isLoading}
          />
        )}

        {/* Tab: IP Quarantine */}
        {currentTab === 'quarantine' && (
          <QuarantineModal
            blockedIps={blockedIps}
            onUnblock={handleUnblockIP}
            onBlock={handleQuarantineIP}
            onRefresh={loadQuarantine}
            isLoading={isLoading}
          />
        )}

        {/* Tab: Traffic Simulator */}
        {currentTab === 'simulation' && (
          <SimulatorDrawer
            status={simulationStatus}
            onStart={async () => {
              const res = await api.startSimulation();
              setSimulationStatus(res);
            }}
            onStop={async () => {
              const res = await api.stopSimulation();
              setSimulationStatus(res);
            }}
            onConfigure={async (cfg) => {
              const res = await api.configureSimulation(cfg);
              setSimulationStatus(res);
            }}
            onTriggerScenario={async (scenario, target) => {
              const res = await api.triggerScenario(scenario, target);
              await loadAlerts();
              await loadDashboardData();
              return res;
            }}
          />
        )}

        {/* Tab: DB Scanner */}
        {currentTab === 'dbms' && (
          <DatabaseScanner
            onScanCompleted={loadDashboardData}
            onAttachedSuccessfully={async () => {
              await loadAlerts();
              await loadDashboardData();
            }}
          />
        )}
      </main>

      {/* Alert Investigation Modal */}
      <AlertModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onUpdateStatus={handleUpdateAlertStatus}
        onQuarantine={handleQuarantineFromAlert}
      />

      {/* Login Modal */}
      <LoginModal
        isOpen={isLoginOpen}
        onClose={() => setIsLoginOpen(false)}
        onLogin={handleLogin}
      />

      {/* Footer */}
      <footer className="mt-auto py-4 border-t border-slate-900 bg-slate-950 text-slate-500 text-xs font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>NIDS Hybrid Engine: Rules + Isolation Forest Active</span>
          </div>
          <div>
            Built with React, TypeScript, Tailwind CSS, FastAPI & SQLite
          </div>
        </div>
      </footer>
    </div>
  );
};
export default App;
