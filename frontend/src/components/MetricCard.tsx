import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  icon: React.ReactNode;
  trend?: string;
  badge?: string;
  variant?: 'cyan' | 'rose' | 'amber' | 'emerald' | 'purple';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  badge,
  variant = 'cyan'
}) => {
  const variantStyles = {
    cyan: 'border-cyan-500/20 bg-slate-900/60 text-cyan-400 hover:border-cyan-500/40',
    rose: 'border-rose-500/20 bg-slate-900/60 text-rose-400 hover:border-rose-500/40',
    amber: 'border-amber-500/20 bg-slate-900/60 text-amber-400 hover:border-amber-500/40',
    emerald: 'border-emerald-500/20 bg-slate-900/60 text-emerald-400 hover:border-emerald-500/40',
    purple: 'border-purple-500/20 bg-slate-900/60 text-purple-400 hover:border-purple-500/40',
  };

  const iconBg = {
    cyan: 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400',
    rose: 'bg-rose-500/10 border-rose-500/20 text-rose-400',
    amber: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
    emerald: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
    purple: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
  };

  return (
    <div className={`p-4 rounded-xl border backdrop-blur-sm transition-all duration-200 ${variantStyles[variant]}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
          {title}
        </span>
        <div className={`p-2 rounded-lg border ${iconBg[variant]}`}>
          {icon}
        </div>
      </div>
      <div className="flex items-baseline justify-between">
        <div className="text-2xl sm:text-3xl font-bold font-mono text-white tracking-tight">
          {value}
        </div>
        {badge && (
          <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300">
            {badge}
          </span>
        )}
      </div>
      <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
        <span>{subtitle}</span>
        {trend && (
          <span className="font-mono text-cyan-400 font-semibold">{trend}</span>
        )}
      </div>
    </div>
  );
};
