import React, { useState } from 'react';
import { 
  Cpu, Play, Square, Zap, ShieldAlert, Radio, 
  Terminal, CheckCircle2, AlertTriangle, Layers, Sliders 
} from 'lucide-react';
import type { SimulationStatus } from '../types';

interface SimulatorDrawerProps {
  status: SimulationStatus | null;
  onStart: () => Promise<void>;
  onStop: () => Promise<void>;
  onConfigure: (config: any) => Promise<void>;
  onTriggerScenario: (scenario: string, target?: string) => Promise<any>;
}

export const SimulatorDrawer: React.FC<SimulatorDrawerProps> = ({
  status,
  onStart,
  onStop,
  onConfigure,
  onTriggerScenario
}) => {
  const [rate, setRate] = useState<number>(status?.rate_flows_per_second || 2.0);
  const [prob, setProb] = useState<number>(status?.attack_probability || 0.25);
  const [triggering, setTriggering] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<any | null>(null);

  const handleRateChange = async (newRate: number) => {
    setRate(newRate);
    await onConfigure({ rate_flows_per_second: newRate });
  };

  const handleProbChange = async (newProb: number) => {
    setProb(newProb);
    await onConfigure({ attack_probability: newProb });
  };

  const handleTrigger = async (scenario: string) => {
    setTriggering(scenario);
    setLastResult(null);
    try {
      const res = await onTriggerScenario(scenario);
      setLastResult(res);
    } catch (e: any) {
      setLastResult({ error: e.message });
    } finally {
      setTriggering(null);
    }
  };

  const scenarios = [
    {
      id: 'port_scan',
      name: 'Port Scanning Recon',
      desc: 'Generates rapid reconnaissance probing 8 distinct ports on destination host.',
      severity: 'High',
      badge: 'Port Scan'
    },
    {
      id: 'brute_force',
      name: 'SSH Credential Brute-Force',
      desc: 'Fires repeated authentication attempts targeting port 22 in short sliding window.',
      severity: 'High',
      badge: 'Auth Attack'
    },
    {
      id: 'ddos_flood',
      name: 'Volumetric SYN/HTTP Flood',
      desc: 'Spikes traffic with high-packet volumetric surge towards target web server.',
      severity: 'Critical',
      badge: 'DDoS Flood'
    },
    {
      id: 'suspicious_outbound',
      name: 'Data Exfiltration / Trojan Port',
      desc: 'Simulates outbound C2 reverse shell on port 4444 with multi-megabyte exfiltration payload.',
      severity: 'Critical',
      badge: 'Exfiltration'
    },
    {
      id: 'arp_spoof',
      name: 'ARP Cache Poisoning (MitM)',
      desc: 'Transmits conflicting hardware MAC frames claiming gateway IP identity.',
      severity: 'Critical',
      badge: 'L2 Poisoning'
    },
    {
      id: 'blacklist_comm',
      name: 'Malicious Threat Intel C2 Beacon',
      desc: 'Simulates beaconing traffic to known Tor exit / global botnet threat feed IP.',
      severity: 'Critical',
      badge: 'C2 Intel'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Top Controller Panel */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-wide">
                Safe Synthetic Traffic & Threat Simulator
              </h2>
              <p className="text-xs text-slate-400">
                Generate safe synthetic traffic mixtures and execute controlled intrusion patterns to evaluate NIDS rules.
              </p>
            </div>
          </div>

          {/* Generator Start/Stop button */}
          <div className="flex items-center gap-3">
            <div className="text-right font-mono text-xs hidden sm:block">
              <div className="text-slate-400">Generator Engine</div>
              <div className={status?.is_running ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                {status?.is_running ? 'RUNNING (AUTO-GEN)' : 'STOPPED'}
              </div>
            </div>
            {status?.is_running ? (
              <button
                onClick={onStop}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs flex items-center gap-2 transition-colors shadow-lg shadow-rose-950/40"
              >
                <Square className="w-4 h-4 fill-white" />
                Stop Simulation
              </button>
            ) : (
              <button
                onClick={onStart}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-2 transition-colors shadow-lg shadow-emerald-950/40"
              >
                <Play className="w-4 h-4 fill-white" />
                Start Simulation
              </button>
            )}
          </div>
        </div>

        {/* Sliders for Rate and Attack Probability */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-slate-800 text-xs">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                Traffic Ingestion Rate
              </span>
              <span className="font-mono text-cyan-400 font-bold">{rate.toFixed(1)} flows/sec</span>
            </div>
            <input
              type="range"
              min="0.5"
              max="10.0"
              step="0.5"
              value={rate}
              onChange={(e) => handleRateChange(parseFloat(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
              <span>0.5 /s</span>
              <span>5.0 /s</span>
              <span>10.0 /s</span>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                Attack Scenario Probability
              </span>
              <span className="font-mono text-rose-400 font-bold">{(prob * 100).toFixed(0)}%</span>
            </div>
            <input
              type="range"
              min="0.05"
              max="0.60"
              step="0.05"
              value={prob}
              onChange={(e) => handleProbChange(parseFloat(e.target.value))}
              className="w-full accent-rose-500 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
              <span>5% (Low Intrusion)</span>
              <span>25% (Balanced)</span>
              <span>60% (Attack Surge)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Trigger Feedback Banner */}
      {lastResult && (
        <div className={`p-4 rounded-xl border text-xs font-mono flex items-start gap-3 ${
          lastResult.error
            ? 'bg-rose-950/60 border-rose-800 text-rose-300'
            : 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
        }`}>
          {lastResult.error ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          )}
          <div>
            <div className="font-bold">
              {lastResult.error
                ? `Trigger Failed: ${lastResult.error}`
                : `Scenario '${lastResult.scenario}' Executed Successfully!`}
            </div>
            {!lastResult.error && (
              <div className="text-[11px] text-emerald-200 mt-1">
                Generated {lastResult.flows_generated} flow packets. NIDS detection engine triggered {lastResult.alerts_triggered} new security alert(s).
              </div>
            )}
          </div>
        </div>
      )}

      {/* Controlled Attack Scenarios Grid */}
      <div>
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" />
          On-Demand Controlled Attack Vector Triggers
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((sc) => {
            const isFiring = triggering === sc.id;
            return (
              <div
                key={sc.id}
                className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm flex flex-col justify-between hover:border-slate-700 transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] uppercase font-bold font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {sc.badge}
                    </span>
                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border ${
                      sc.severity === 'Critical'
                        ? 'bg-rose-950 text-rose-400 border-rose-800'
                        : 'bg-orange-950 text-orange-400 border-orange-800'
                    }`}>
                      {sc.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-white mb-1.5 font-sans">
                    {sc.name}
                  </h4>
                  <p className="text-xs text-slate-400 mb-4 font-sans leading-relaxed">
                    {sc.desc}
                  </p>
                </div>

                <button
                  onClick={() => handleTrigger(sc.id)}
                  disabled={isFiring}
                  className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-cyan-600 hover:text-white text-cyan-400 border border-slate-700 hover:border-cyan-500 font-semibold text-xs transition-all flex items-center justify-center gap-2 font-sans"
                >
                  <Zap className={`w-3.5 h-3.5 ${isFiring ? 'animate-bounce text-amber-400' : ''}`} />
                  {isFiring ? 'Injecting Attack...' : 'Launch Vector Now'}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
