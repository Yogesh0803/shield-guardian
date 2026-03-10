import React from 'react';

interface SkeletonProps {
  className?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className = '' }) => (
  <div className={`animate-pulse bg-slate-700/50 rounded ${className}`} />
);

export const StatCardSkeleton: React.FC = () => (
  <div className="bg-slate-800 border border-slate-700/60 rounded-lg p-5">
    <Skeleton className="h-4 w-24 mb-3" />
    <Skeleton className="h-7 w-16 mb-2" />
    <Skeleton className="h-3 w-20" />
  </div>
);

export const TableSkeleton: React.FC<{ rows?: number }> = ({ rows = 5 }) => (
  <div className="space-y-3">
    <Skeleton className="h-10 w-full" />
    {Array.from({ length: rows }).map((_, i) => (
      <Skeleton key={i} className="h-12 w-full" />
    ))}
  </div>
);

export const ChartSkeleton: React.FC = () => (
  <div className="bg-slate-800 border border-slate-700/60 rounded-lg p-5">
    <Skeleton className="h-4 w-32 mb-4" />
    <Skeleton className="h-64 w-full" />
  </div>
);
