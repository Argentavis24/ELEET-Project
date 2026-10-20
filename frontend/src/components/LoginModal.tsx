import React, { useState } from 'react';
import { Lock, User, Key, X, ShieldAlert, Check } from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLogin: (user: string, pass: string) => Promise<void>;
}

export const LoginModal: React.FC<LoginModalProps> = ({
  isOpen,
  onClose,
  onLogin
}) => {
  if (!isOpen) return null;

  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('Analyst2026!');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      await onLogin(username, password);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const setAdminCreds = () => {
    setUsername('admin');
    setPassword('CyberDefense2026!');
  };

  const setAnalystCreds = () => {
    setUsername('analyst');
    setPassword('Analyst2026!');
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="relative w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Lock className="w-4 h-4" />
            </div>
            <span className="font-bold text-white tracking-wide text-sm">
              Analyst Authentication
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs font-mono">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs text-slate-400 mb-1">Username</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Password</label>
            <div className="relative">
              <Key className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Quick Credential Pre-fills */}
          <div className="pt-2">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1.5 font-bold">
              Demo Credentials (Click to pre-fill)
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={setAnalystCreds}
                className="flex-1 py-1 px-2 rounded bg-slate-950 border border-slate-800 hover:border-cyan-500/50 text-[11px] font-mono text-cyan-400 transition-colors text-center"
              >
                analyst / Analyst2026!
              </button>
              <button
                type="button"
                onClick={setAdminCreds}
                className="flex-1 py-1 px-2 rounded bg-slate-950 border border-slate-800 hover:border-cyan-500/50 text-[11px] font-mono text-cyan-400 transition-colors text-center"
              >
                admin / CyberDefense2026!
              </button>
            </div>
          </div>

          <div className="pt-3">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors shadow-lg shadow-cyan-950/50 flex items-center justify-center gap-2"
            >
              <Lock className="w-3.5 h-3.5" />
              {isLoading ? 'Verifying Credentials...' : 'Authenticate & Access SOC'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
