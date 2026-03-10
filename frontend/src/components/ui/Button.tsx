import React from 'react';

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
type Size = 'sm' | 'md' | 'lg';

const variantStyles: Record<Variant, string> = {
  primary: 'bg-blue-600 hover:bg-blue-700 text-white shadow-sm',
  secondary: 'bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600',
  danger: 'bg-red-600 hover:bg-red-700 text-white',
  ghost: 'hover:bg-slate-700/50 text-slate-400 hover:text-slate-200',
  outline: 'border border-slate-600 hover:border-blue-500/50 text-slate-300 hover:text-blue-400',
};

const sizeStyles: Record<Size, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-5 py-2.5 text-sm',
};

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  icon,
  className = '',
  disabled,
  ...props
}) => (
  <button
    className={`inline-flex items-center justify-center gap-2 font-medium rounded-md transition-colors duration-150
      ${variantStyles[variant]} ${sizeStyles[size]}
      ${disabled || loading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
      ${className}`}
    disabled={disabled || loading}
    {...props}
  >
    {loading ? (
      <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
    ) : icon ? (
      icon
    ) : null}
    {children}
  </button>
);
