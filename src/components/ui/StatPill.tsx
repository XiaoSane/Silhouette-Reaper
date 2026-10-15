import React from 'react';
import { twMerge } from 'tailwind-merge';

interface StatPillProps {
  label: string;
  value: string | number;
  variant?: 'amber' | 'green' | 'red' | 'neutral' | 'cyan';
  icon?: React.ReactNode;
  className?: string;
}

export const StatPill: React.FC<StatPillProps> = ({
  label,
  value,
  variant = 'neutral',
  icon,
  className,
}) => {
  let styleClasses = 'border-zinc-800 bg-zinc-900/50 text-zinc-300';

  if (variant === 'amber') {
    styleClasses =
      'border-amber-500/30 bg-amber-500/10 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.15)]';
  } else if (variant === 'green') {
    styleClasses =
      'border-emerald-500/30 bg-emerald-500/10 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.15)]';
  } else if (variant === 'red') {
    styleClasses =
      'border-rose-500/30 bg-rose-500/10 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.15)]';
  } else if (variant === 'cyan') {
    styleClasses =
      'border-cyan-500/30 bg-cyan-500/10 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]';
  }

  return (
    <div
      className={twMerge(
        'flex items-center gap-3 rounded-xl border px-4 py-3 backdrop-blur-md',
        styleClasses,
        className
      )}
    >
      {icon && <div className="text-current opacity-80">{icon}</div>}
      <div>
        <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400">
          {label}
        </div>
        <div className="font-mono text-lg font-bold leading-tight text-white">
          {value}
        </div>
      </div>
    </div>
  );
};
