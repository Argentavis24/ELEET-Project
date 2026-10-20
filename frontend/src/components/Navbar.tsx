import React from 'react';
import { 
  ShieldAlert, Activity, Radio, Pause, Play, 
  Lock, Ban, Cpu, UserCheck, LogOut, LogIn, Database 
} from 'lucide-react';
import type { User } from '../types';

interface NavbarProps {
  currentTab: 'dashboard' | 'flows' | 'alerts' | 'quarantine' | 'simulation' | 'dbms';
  setCurrentTab: (tab: 'dashboard' | 'flows' | 'alerts' | 'quarantine' | 'simulation' | 'dbms') => void;
  activeAlertsCount: number;
  isWsConnected: boolean;
  isStreamPaused: boolean;
  setIsStreamPaused: (paused: boolean) => void;
  user: User | null;
  onOpenLogin: () => void;
  onLogout: () => void;
  quarantinedCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  activeAlertsCount,
  isWsConnected,
  isStreamPaused,
  setIsStreamPaused,
  user,
  onOpenLogin,
  onLogout,
  quarantinedCount
}) => {
  return (
    <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 text-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400 flex items-center justify-center">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-wider text-white">CYBERDEFEND</span>
                <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                  NIDS v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono hidden sm:block">
                Network Intrusion Detection & Real-time Threat Defense
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            <button
              onClick={() => setCurrentTab('dashboard')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-2 ${
                currentTab === 'dashboard'
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Activity className="w-4 h-4" />
              Overview
            </button>

            <button
              onClick={() => setCurrentTab('alerts')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-2 ${
                currentTab === 'alerts'
                  ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              Alerts
              {activeAlertsCount > 0 && (
                <span className="ml-1 px-1.5 py-0.2 text-xs font-mono rounded-full bg-rose-500 text-white animate-bounce">
                  {activeAlertsCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setCurrentTab('flows')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-2 ${
                currentTab === 'flows'
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Radio className="w-4 h-4" />
              Live Flows
            </button>

            <button
              onClick={() => setCurrentTab('quarantine')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-2 ${
                currentTab === 'quarantine'
                  ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Ban className="w-4 h-4" />
              Quarantine
              {quarantinedCount > 0 && (
                <span className="ml-1 px-1.5 py-0.2 text-xs font-mono rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  {quarantinedCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setCurrentTab('simulation')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-2 ${
                currentTab === 'simulation'
                  ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Cpu className="w-4 h-4" />
              Simulator
            </button>

            <button
              onClick={() => setCurrentTab('dbms')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-2 ${
                currentTab === 'dbms'
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Database className="w-4 h-4" />
              DB Scanner
            </button>
          </nav>

          {/* Right Status Controls */}
          <div className="flex items-center gap-3">
            {/* Stream pause/play toggle */}
            <button
              onClick={() => setIsStreamPaused(!isStreamPaused)}
              title={isStreamPaused ? 'Resume live WebSocket stream' : 'Pause live stream'}
              className={`p-1.5 rounded-md border text-xs font-mono flex items-center gap-1.5 transition-colors ${
                isStreamPaused
                  ? 'bg-amber-950/60 border-amber-600/40 text-amber-400 hover:bg-amber-900/40'
                  : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {isStreamPaused ? (
                <>
                  <Play className="w-3.5 h-3.5 text-amber-400" />
                  <span className="hidden sm:inline">PAUSED</span>
                </>
              ) : (
                <>
                  <Pause className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="hidden sm:inline">LIVE</span>
                </>
              )}
            </button>

            {/* Connection pill */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-950 border border-slate-800 text-xs font-mono">
              <span className={`w-2 h-2 rounded-full ${isWsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className="text-slate-400 hidden sm:inline">
                {isWsConnected ? 'SOC FEED ONLINE' : 'OFFLINE'}
              </span>
            </div>

            {/* User profile / auth */}
            {user ? (
              <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
                <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-800 text-xs">
                  <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-mono text-slate-300">{user.username}</span>
                  <span className="text-[10px] uppercase font-bold text-cyan-400 px-1 py-0.2 bg-cyan-950/60 rounded border border-cyan-800">
                    {user.role}
                  </span>
                </div>
                <button
                  onClick={onLogout}
                  title="Logout"
                  className="p-1.5 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <button
                onClick={onOpenLogin}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 transition-colors"
              >
                <LogIn className="w-3.5 h-3.5" />
                Login
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
