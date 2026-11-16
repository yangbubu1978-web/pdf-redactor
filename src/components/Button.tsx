import React from 'react';

type Variant = 'primary' | 'purple' | 'danger' | 'ghost' | 'rainbow';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  isLoading?: boolean;
  icon?: React.ReactNode;
}

const base =
  'inline-flex items-center justify-center gap-2 rounded-2xl font-black tracking-tight transition-all active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none';

const variants: Record<Variant, string> = {
  primary:
    'bg-slate-900 text-white shadow-lg shadow-slate-900/20 hover:bg-slate-800',
  purple:
    'bg-gradient-to-r from-violet-600 to-fuchsia-500 text-white shadow-lg shadow-violet-500/30 hover:brightness-110',
  danger:
    'bg-rose-500 text-white shadow-lg shadow-rose-500/25 hover:bg-rose-600',
  ghost:
    'bg-white text-slate-700 border border-slate-200 shadow-sm hover:border-slate-300',
  rainbow:
    'bg-gradient-to-r from-cyan-500 via-violet-500 to-fuchsia-500 text-white shadow-lg shadow-violet-500/30 hover:brightness-110',
};

export function Button({
  variant = 'primary',
  isLoading,
  icon,
  children,
  className = '',
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={`${base} ${variants[variant]} px-4 py-3 text-sm ${className}`}
      disabled={disabled || isLoading}
      {...rest}
    >
      {isLoading ? (
        <span className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin" />
      ) : (
        icon
      )}
      {children}
    </button>
  );
}

export default Button;
