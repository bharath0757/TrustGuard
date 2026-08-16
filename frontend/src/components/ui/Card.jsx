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
          'rounded-xl bg-white border border-[#C7D0DA] shadow-xs overflow-hidden text-[#182230]',
          className
        )}
        {...props}
      >
        {header && (
          <div className="px-5 py-3.5 border-b border-[#D5DDE5] bg-[#F1F4F7] flex items-center justify-between text-sm font-semibold text-[#182230]">
            {header}
          </div>
        )}
        <div className="p-5">{children}</div>
        {footer && (
          <div className="px-5 py-3.5 border-t border-[#D5DDE5] bg-[#F1F4F7]">
            {footer}
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      className={cn(
        'rounded-xl bg-white border border-[#C7D0DA] shadow-xs text-[#182230]',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

