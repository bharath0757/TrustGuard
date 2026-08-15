import React from 'react';
import { NavLink } from 'react-router-dom';
import { ShieldCheck, ChevronLeft } from 'lucide-react';
import { NAVIGATION_ITEMS } from '../../data/navigation';
import { useTrustGuard } from '../../hooks/useTrustGuard';
import { cn } from '../../utils/cn';
import { Badge, Button } from '../ui';

export function Sidebar() {
  const { sidebarCollapsed, toggleSidebar } = useTrustGuard();

  const handleNavClick = () => {
    if (typeof window !== 'undefined' && window.innerWidth < 1024 && !sidebarCollapsed) {
      toggleSidebar();
    }
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {!sidebarCollapsed && (
        <div
          className="fixed inset-0 z-30 bg-slate-900/40 lg:hidden transition-opacity"
          onClick={toggleSidebar}
        />
      )}

      <aside
        className={cn(
          'fixed lg:static top-0 bottom-0 left-0 z-40 flex flex-col w-64 bg-white border-r border-[#C7D0DA] dark:border-slate-800 transition-all duration-200 ease-in-out',
          sidebarCollapsed ? '-translate-x-full lg:translate-x-0 lg:w-20' : 'translate-x-0'
        )}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-[#C7D0DA] dark:border-slate-800 bg-white">
          <NavLink to="/" onClick={handleNavClick} className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-[#17324D] flex items-center justify-center text-white shrink-0 shadow-xs">
              <ShieldCheck className="w-5 h-5" />
            </div>
            {!sidebarCollapsed && (
              <div className="flex flex-col min-w-0">
                <span className="font-bold tracking-tight text-[#17324D] text-sm leading-tight">
                  TrustGuard
                </span>
                <span className="text-[11px] text-[#667085] truncate">
                  Examination Security
                </span>
              </div>
            )}
          </NavLink>

          <Button
            variant="ghost"
            size="icon"
            onClick={toggleSidebar}
            className="hidden lg:flex text-[#667085] hover:text-[#17324D] p-1.5"
            aria-label="Toggle Sidebar"
          >
            <ChevronLeft
              className={cn(
                'w-4 h-4 transition-transform duration-200',
                sidebarCollapsed && 'rotate-180'
              )}
            />
          </Button>
        </div>

        {/* Navigation List */}
        <div className="flex-1 overflow-y-auto py-4 px-3 bg-white">
          <nav className="space-y-1">
            {NAVIGATION_ITEMS.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  onClick={handleNavClick}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors',
                      isActive
                        ? 'bg-[#F0F5F9] text-[#17324D] font-semibold border border-[#D5DDE5]'
                        : 'text-[#475467] hover:text-[#17324D] hover:bg-[#F1F4F7] border border-transparent'
                    )
                  }
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  {!sidebarCollapsed && (
                    <span className="flex-1 truncate">{item.name}</span>
                  )}
                  {!sidebarCollapsed && item.badge && (
                    <Badge
                      variant={item.badgeVariant || 'neutral'}
                      size="sm"
                      className="ml-auto text-[10px] px-1.5 py-0"
                    >
                      {item.badge}
                    </Badge>
                  )}
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* Subtle Footer */}
        <div className="p-3 border-t border-[#C7D0DA] dark:border-slate-800 bg-[#F1F4F7]">
          {!sidebarCollapsed ? (
            <div className="p-2.5 rounded-lg bg-white border border-[#D5DDE5] text-xs">
              <span className="font-semibold text-[#17324D] block">Security Policy Active</span>
              <p className="text-[11px] text-[#667085] mt-0.5 leading-tight">
                Access control policy enforced across all nodes.
              </p>
            </div>
          ) : (
            <div className="flex justify-center text-[#667085] py-1">
              <ShieldCheck className="w-4 h-4 text-[#17324D]" />
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
