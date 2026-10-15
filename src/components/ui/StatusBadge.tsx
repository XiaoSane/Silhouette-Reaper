import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md';
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  size = 'md',
  className,
}) => {
  const norm = status.toUpperCase();

  let colorClasses = 'bg-zinc-800/60 border-zinc-700/60 text-zinc-400';

  if (
    ['VERIFIED', 'PRESERVED_RO', 'SUCCESS', 'COMPLETED', 'DEFINITIVE', 'AUTHENTIC_AND_VERIFIED', 'LOW', 'INFORMATIONAL'].includes(
      norm
    )
  ) {
    colorClasses =
      'bg-emerald-500/10 border-emerald-500/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.15)]';
  } else if (
    ['HIGH', 'CRITICAL', 'FAILED', 'MISMATCH', 'TAMPER_DETECTED', 'SECURITY_EVENT', 'EXTENSION_SPOOF'].includes(
      norm
    )
  ) {
    colorClasses =
      'bg-rose-500/10 border-rose-500/40 text-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.2)]';
  } else if (
    ['MEDIUM', 'WARNING', 'PROCESSING', 'RUNNING', 'EXAMINATION', 'QUEUED', 'EVIDENCE_REGISTERED', 'HEURISTIC', 'EMBEDDED_OBJECT'].includes(
      norm
    )
  ) {
    colorClasses =
      'bg-amber-500/10 border-amber-500/40 text-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.2)]';
  } else if (['CREATED', 'EVIDENCE_PENDING', 'INFO', 'INFERRED'].includes(norm)) {
    colorClasses = 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400';
  }

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={twMerge(
        'inline-flex items-center gap-1.5 font-mono font-bold uppercase tracking-wider rounded-md border',
        sizeClass,
        colorClasses,
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80 animate-pulse" />
      {status}
    </span>
  );
};
