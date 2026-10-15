import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface GlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'amber' | 'subtle';
  interactive?: boolean;
}

export const GlassCard: React.FC<GlassCardProps> = ({
  children,
  className,
  variant = 'default',
  interactive = false,
  ...props
}) => {
  const variantClass =
    variant === 'amber'
      ? 'glass-panel-amber'
      : variant === 'subtle'
      ? 'glass-panel-subtle'
      : 'glass-panel';

  return (
    <div
      className={twMerge(
        'rounded-xl p-5 backdrop-blur-md',
        variantClass,
        interactive &&
          'hover:border-amber-400/60 hover:shadow-[0_0_25px_rgba(245,158,11,0.25)] hover:-translate-y-0.5 cursor-pointer',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};
