import React from 'react';
import { cn } from '../../utils/cn';

const variants = {
  default: 'bg-[#F0F4F8] text-[#182230] border-[#C7D0DA]',
  info: 'bg-[#EAF2F8] text-[#17324D] border-[#C7D0DA]',
  success: 'bg-[#EAF5F0] text-[#2E7D5B] border-[#B2D8C7]',
  warning: 'bg-[#FAF3E7] text-[#B7791F] border-[#E8D4B5]',
  danger: 'bg-[#FDF2F2] text-[#C44747] border-[#F2C2C2]',
  neutral: 'bg-[#F0F4F8] text-[#5E6B78] border-[#C7D0DA]',
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
