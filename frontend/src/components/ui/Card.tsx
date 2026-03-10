import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
}

export const Card: React.FC<CardProps> = ({ children, className = '', hover = false }) => (
  <div
    className={`bg-slate-800 border border-slate-700/60 rounded-lg ${
      hover ? 'hover:border-slate-600 transition-colors duration-150' : ''
    } ${className}`}
  >
    {children}
  </div>
);

export const CardHeader: React.FC<{ children: React.ReactNode; className?: string }> = ({
  children,
  className = '',
}) => <div className={`px-5 py-3.5 border-b border-slate-700/60 ${className}`}>{children}</div>;

export const CardContent: React.FC<{ children: React.ReactNode; className?: string }> = ({
  children,
  className = '',
}) => <div className={`px-5 py-4 ${className}`}>{children}</div>;
