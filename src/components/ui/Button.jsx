import React from 'react';
import { cn } from '../../utils/cn';

const variants = {
  primary: 'bg-[#17324D] hover:bg-[#1e3f60] text-white font-medium shadow-xs border border-transparent active:scale-[0.99]',
  secondary: 'bg-white hover:bg-[#F9FAFB] text-[#344054] font-medium border border-[#D0D5DD] shadow-xs active:bg-[#F2F4F7]',
  danger: 'bg-[#C44747] hover:bg-[#ab3c3c] text-white font-medium shadow-xs border border-transparent',
  outline: 'border border-[#D0D5DD] hover:border-[#98A2B3] text-[#344054] hover:text-[#1F2933] bg-white hover:bg-[#F9FAFB] shadow-xs',
  ghost: 'text-[#475467] hover:text-[#1F2933] hover:bg-[#F2F4F7] bg-transparent',
};

const sizes = {
  sm: 'px-2.5 py-1.5 text-xs rounded-md gap-1.5',
  md: 'px-3.5 py-2 text-sm rounded-lg gap-2',
  lg: 'px-4.5 py-2.5 text-sm rounded-lg gap-2',
  icon: 'p-2 rounded-lg',
};

export function Button({
  children,
  variant = 'primary',
  size = 'md',
  className,
  disabled = false,
  loading = false,
  icon: Icon,
  iconPosition = 'left',
  ...props
}) {
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center transition-colors duration-150 font-medium focus:outline-none focus:ring-2 focus:ring-[#17324D]/20 focus:border-[#17324D] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer select-none',
        variants[variant] || variants.primary,
        sizes[size] || sizes.md,
        className
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin shrink-0" />
      )}
      {!loading && Icon && iconPosition === 'left' && <Icon className="w-4 h-4 shrink-0" />}
      {children}
      {!loading && Icon && iconPosition === 'right' && <Icon className="w-4 h-4 shrink-0" />}
    </button>
  );
}
