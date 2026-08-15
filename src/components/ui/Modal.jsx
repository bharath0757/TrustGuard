import React, { useEffect } from 'react';
import { X } from 'lucide-react';
import { cn } from '../../utils/cn';
import { Button } from './Button';

export function Modal({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  footer,
  maxWidth = 'max-w-lg',
  className,
}) {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    if (isOpen) {
      document.body.style.overflow = 'hidden';
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.body.style.overflow = 'unset';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-900/50 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      {/* Modal Dialog */}
      <div
        className={cn(
          'relative w-full rounded-xl border border-[#C7D0DA] dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl z-10 overflow-hidden text-[#1F2933] dark:text-slate-100 max-h-[92vh] flex flex-col',
          maxWidth,
          className
        )}
      >
        {/* Header */}
        <div className="flex items-start justify-between px-4 sm:px-6 py-3.5 sm:py-4 border-b border-[#D5DDE5] dark:border-slate-800 bg-[#F1F4F7] dark:bg-slate-900/70 shrink-0">
          <div className="min-w-0 pr-2">
            {title && <h3 className="text-sm sm:text-base font-bold text-[#17324D] dark:text-slate-100 truncate">{title}</h3>}
            {subtitle && <p className="text-xs text-[#667085] dark:text-slate-400 mt-0.5 truncate">{subtitle}</p>}
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={onClose}
            className="text-[#667085] hover:text-[#1F2933] dark:text-slate-400 dark:hover:text-slate-100 -mr-1.5 -mt-1 shrink-0 p-1"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </Button>
        </div>

        {/* Body Content with smooth internal scroll */}
        <div className="px-4 sm:px-6 py-4 sm:py-5 overflow-y-auto flex-1">{children}</div>

        {/* Footer (Optional) */}
        {footer && (
          <div className="px-4 sm:px-6 py-3 border-t border-[#D5DDE5] dark:border-slate-800 bg-[#F1F4F7] dark:bg-slate-900/70 flex items-center justify-end gap-3 shrink-0">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
