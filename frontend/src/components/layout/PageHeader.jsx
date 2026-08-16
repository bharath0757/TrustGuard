import React from 'react';
import { cn } from '../../utils/cn';

export function PageHeader({
  title,
  subtitle,
  breadcrumb,
  action,
  className,
}) {
  return (
    <div className={cn('pb-5 border-b border-[#E4E7EC] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4', className)}>
      <div className="space-y-1">
        {breadcrumb && (
          <div className="text-xs text-[#667085] font-medium mb-1">
            {breadcrumb}
          </div>
        )}
        {title && (
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#17324D]">
            {title}
          </h1>
        )}
        {subtitle && (
          <p className="text-xs sm:text-sm text-[#667085] font-normal max-w-3xl">
            {subtitle}
          </p>
        )}
      </div>

      {action && (
        <div className="flex items-center gap-2.5 shrink-0 self-start sm:self-auto">
          {action}
        </div>
      )}
    </div>
  );
}
