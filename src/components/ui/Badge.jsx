import React from 'react';
import { cn } from '../../utils/cn';

const variants = {
  default: 'bg-[#F2F4F7] text-[#344054] border-[#EAECF0]',
  info: 'bg-[#F0F5F9] text-[#17324D] border-[#D8E6F0]',
  success: 'bg-[#ECFDF3] text-[#2E7D5B] border-[#D1FADF]',
  warning: 'bg-[#FFFAEB] text-[#B7791F] border-[#FEDF89]',
  danger: 'bg-[#FEF3F2] text-[#C44747] border-[#FECDCA]',
  neutral: 'bg-[#F8F9FA] text-[#475467] border-[#E4E7EC]',
};

const sizes = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

export function Badge({
  children,
  variant = 'default',
  size = 'md',
  className,
  dot = false,
  ...props
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center font-medium rounded-md border tracking-tight',
        variants[variant] || variants.default,
        sizes[size] || sizes.md,
        className
      )}
      {...props}
    >
      {dot && (
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full mr-1.5 shrink-0',
            variant === 'success' && 'bg-[#2E7D5B]',
            variant === 'danger' && 'bg-[#C44747]',
            variant === 'warning' && 'bg-[#B7791F]',
            variant === 'info' && 'bg-[#17324D]',
            variant === 'default' && 'bg-[#475467]',
            variant === 'neutral' && 'bg-[#667085]'
          )}
        />
      )}
      {children}
    </span>
  );
}
