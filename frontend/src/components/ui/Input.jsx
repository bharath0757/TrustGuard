import React from 'react';
import { cn } from '../../utils/cn';

export function Input({
  label,
  error,
  icon: Icon,
  className,
  wrapperClassName,
  ...props
}) {
  return (
    <div className={cn('space-y-1.5', wrapperClassName)}>
      {label && (
        <label className="block text-xs font-semibold text-[#344054]">
          {label}
        </label>
      )}
      <div className="relative rounded-lg shadow-xs">
        {Icon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#667085]">
            <Icon className="w-4 h-4" />
          </div>
        )}
        <input
          className={cn(
            'w-full bg-white border border-[#D0D5DD] rounded-lg text-[#1F2933] placeholder-[#98A2B3] text-sm focus:outline-none focus:ring-2 focus:ring-[#17324D]/10 focus:border-[#17324D] transition-all duration-150 py-2',
            Icon ? 'pl-9 pr-3' : 'px-3',
            error && 'border-[#C44747] focus:ring-[#C44747]/10 focus:border-[#C44747]',
            className
          )}
          {...props}
        />
      </div>
      {error && <p className="text-xs text-[#C44747] font-medium">{error}</p>}
    </div>
  );
}
