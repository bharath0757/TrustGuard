import React from 'react';
import { useLocation } from 'react-router-dom';
import { Menu, User, ShieldCheck, RotateCcw } from 'lucide-react';
import { useTrustGuard } from '../../hooks/useTrustGuard';
import { Button } from '../ui';

const ROUTE_NAMES = {
  '/': 'Dashboard',
  '/papers': 'Question Papers',
  '/approvals': 'Approvals',
  '/threat-alerts': 'Threat Alerts',
  '/alerts': 'Threat Alerts',
  '/attack-simulator': 'Attack Simulator',
  '/audit': 'Audit Trail',
  '/exam-center': 'Exam Center',
};

export function Topbar() {
  const location = useLocation();
  const { toggleSidebar, resetDemoState } = useTrustGuard();

  const currentRouteName = ROUTE_NAMES[location.pathname] || 'Dashboard';

  return (
    <header className="sticky top-0 z-30 h-16 border-b border-[#C7D0DA] bg-white px-4 sm:px-6 flex items-center justify-between shadow-xs transition-colors duration-150">
      {/* Left: Mobile Toggle & Breadcrumb */}
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          className="text-[#667085] hover:text-[#182230] lg:hidden p-1.5"
          aria-label="Toggle menu"
        >
          <Menu className="w-5 h-5" />
        </Button>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-[#667085] hidden sm:inline font-medium">TrustGuard</span>
          <span className="text-[#D5DDE5] hidden sm:inline">/</span>
          <span className="text-[#17324D] font-semibold text-sm">{currentRouteName}</span>
        </div>
      </div>

      {/* Right: System Status, Reset Demo & User Profile */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* System Status: Secure */}
        <div className="hidden sm:flex items-center gap-2 bg-[#ECFDF3] border border-[#D1FADF] px-3 py-1.5 rounded-md text-xs">
          <span className="w-2 h-2 rounded-full bg-[#2E7D5B] shrink-0" />
          <span className="font-semibold text-[#2E7D5B]">System status: Secure</span>
        </div>

        {/* Quick Reset Demo Action */}
        <button
          type="button"
          onClick={resetDemoState}
          title="Reset Demo State"
          aria-label="Reset Demo State"
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-[#475467] hover:text-[#17324D] bg-[#F1F4F7] hover:bg-[#E4E7EC] border border-[#D5DDE5] transition-colors cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Reset Demo</span>
        </button>

        {/* User / Profile */}
        <div className="flex items-center gap-2.5 pl-2 sm:pl-3 border-l border-[#D5DDE5]">
          <div className="w-8 h-8 rounded-full bg-[#F0F5F9] border border-[#D5DDE5] flex items-center justify-center text-[#17324D] text-xs font-semibold">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden md:flex flex-col text-left">
            <span className="text-xs font-semibold text-[#182230] leading-tight">
              Exam Administrator
            </span>
            <span className="text-[11px] text-[#667085] leading-tight">
              Authorized Officer
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

// Export as Navbar as well for backward compatibility
export { Topbar as Navbar };

