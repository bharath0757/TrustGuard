import React from 'react';
import { cn } from '../../utils/cn';

export function StatusIndicator({
  status = 'online', // 'online' | 'warning' | 'danger' | 'offline'
  label,
  className,
  pulse = false,
}) {
  const statusStyles = {
    online: { dot: 'bg-[#2E7D5B]', ring: 'bg-[#2E7D5B]/25', text: 'text-[#2E7D5B]' },
    warning: { dot: 'bg-[#B7791F]', ring: 'bg-[#B7791F]/25', text: 'text-[#B7791F]' },
    danger: { dot: 'bg-[#C44747]', ring: 'bg-[#C44747]/25', text: 'text-[#C44747]' },
    offline: { dot: 'bg-[#667085]', ring: 'bg-[#667085]/25', text: 'text-[#667085]' },
  };

  const current = statusStyles[status] || statusStyles.online;

  return (
    <div className={cn('inline-flex items-center gap-2 text-xs', className)}>
      <span className="relative flex h-2 w-2">
        {pulse && (
          <span
            className={cn(
              'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75',
              current.ring
            )}
          />
        )}
        <span className={cn('relative inline-flex rounded-full h-2 w-2', current.dot)} />
      </span>
      {label && <span className={cn('font-medium', current.text)}>{label}</span>}
    </div>
  );
}
