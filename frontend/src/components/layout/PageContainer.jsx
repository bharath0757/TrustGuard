import React from 'react';
import { cn } from '../../utils/cn';
import { PageHeader } from './PageHeader';

export function PageContainer({
  title,
  subtitle,
  breadcrumb,
  action,
  children,
  className,
}) {
  const hasHeader = Boolean(title || subtitle || action || breadcrumb);

  return (
    <div className={cn('max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 space-y-6 text-[#1F2933]', className)}>
      {hasHeader && (
        <PageHeader
          title={title}
          subtitle={subtitle}
          breadcrumb={breadcrumb}
          action={action}
        />
      )}
      {children}
    </div>
  );
}
