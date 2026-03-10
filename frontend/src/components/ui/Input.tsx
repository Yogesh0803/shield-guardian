import React from 'react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

export const Input: React.FC<InputProps> = ({ label, error, icon, className = '', ...props }) => (
  <div className="space-y-1.5">
    {label && <label className="block text-sm font-medium text-slate-300">{label}</label>}
    <div className="relative">
      {icon && <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">{icon}</div>}
      <input
        className={`w-full bg-slate-800 border border-slate-600 rounded-md px-3.5 py-2 text-sm text-slate-200
          placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50
          transition-colors duration-150 ${icon ? 'pl-10' : ''} ${error ? 'border-red-500/50 focus:ring-red-500/30' : ''}
          ${className}`}
        {...props}
      />
    </div>
    {error && <p className="text-xs text-red-400">{error}</p>}
  </div>
);

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  options: { value: string; label: string }[];
}

export const Select: React.FC<SelectProps> = ({ label, error, options, className = '', ...props }) => (
  <div className="space-y-1.5">
    {label && <label className="block text-sm font-medium text-slate-300">{label}</label>}
    <select
      className={`w-full bg-slate-800 border border-slate-600 rounded-md px-3.5 py-2 text-sm text-slate-200
        focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50
        transition-colors duration-150 ${error ? 'border-red-500/50' : ''} ${className}`}
      {...props}
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
    {error && <p className="text-xs text-red-400">{error}</p>}
  </div>
);

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
}

export const Textarea: React.FC<TextareaProps> = ({ label, error, className = '', ...props }) => (
  <div className="space-y-1.5">
    {label && <label className="block text-sm font-medium text-slate-300">{label}</label>}
    <textarea
      className={`w-full bg-slate-800 border border-slate-600 rounded-md px-3.5 py-2 text-sm text-slate-200
        placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50
        transition-colors duration-150 resize-none ${error ? 'border-red-500/50' : ''} ${className}`}
      {...props}
    />
    {error && <p className="text-xs text-red-400">{error}</p>}
  </div>
);
