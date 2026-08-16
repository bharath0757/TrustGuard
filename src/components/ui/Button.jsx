import React from 'react';
import { cn } from '../../utils/cn';

const variants = {
  primary: 'bg-gradient-to-b from-[#17324D] to-[#1F3D5C] hover:from-[#1F3D5C] hover:to-[#17324D] text-white font-semibold shadow-xs hover:shadow-sm border border-[#17324D] hover:-translate-y-0.5 active:translate-y-0',
  secondary: 'bg-white hover:bg-[#F0F4F8] text-[#182230] font-medium border border-[#C7D0DA] shadow-xs hover:border-[#AAB7C4] hover:-translate-y-0.5 active:translate-y-0',
  danger: 'bg-gradient-to-b from-[#C44747] to-[#B03A3A] hover:from-[#B03A3A] hover:to-[#C44747] text-white font-semibold shadow-xs hover:shadow-sm border border-[#C44747] hover:-translate-y-0.5 active:translate-y-0',
  outline: 'border border-[#C7D0DA] hover:border-[#AAB7C4] text-[#182230] bg-white hover:bg-[#F0F4F8] shadow-xs hover:-translate-y-0.5 active:translate-y-0',
  ghost: 'text-[#5E6B78] hover:text-[#182230] hover:bg-[#F0F4F8] bg-transparent',
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
        'inline-flex items-center justify-center transition-all duration-150 font-medium focus:outline-none focus:ring-2 focus:ring-[#17324D]/20 focus:border-[#17324D] disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none cursor-pointer select-none',
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
