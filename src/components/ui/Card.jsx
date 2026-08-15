import React from 'react';
import { cn } from '../../utils/cn';

export function Card({
  children,
  className,
  header,
  footer,
  ...props
}) {
  if (header || footer) {
    return (
      <div
        className={cn(
          'rounded-xl bg-white border border-[#C7D0DA] dark:border-slate-800 shadow-xs overflow-hidden text-[#1F2933] dark:text-slate-100',
          className
        )}
        {...props}
      >
        {header && (
          <div className="px-5 py-3.5 border-b border-[#D5DDE5] dark:border-slate-800 bg-[#F1F4F7] dark:bg-slate-900/60 flex items-center justify-between text-sm font-semibold text-[#1F2933] dark:text-slate-100">
            {header}
          </div>
        )}
        <div className="p-5">{children}</div>
        {footer && (
          <div className="px-5 py-3.5 border-t border-[#D5DDE5] dark:border-slate-800 bg-[#F1F4F7] dark:bg-slate-900/60">
            {footer}
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      className={cn(
        'rounded-xl bg-white border border-[#C7D0DA] dark:border-slate-800 shadow-xs text-[#1F2933] dark:text-slate-100',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}
