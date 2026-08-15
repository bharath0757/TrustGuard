import React from 'react';
import { useLocation } from 'react-router-dom';
import { Menu, User, ShieldCheck, Sun, Moon, RotateCcw } from 'lucide-react';
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
  const { toggleSidebar, theme, setTheme, resetDemoState } = useTrustGuard();

  const currentRouteName = ROUTE_NAMES[location.pathname] || 'Dashboard';
  const isDark = theme === 'dark';

  return (
    <header className="sticky top-0 z-30 h-16 border-b border-[#C7D0DA] dark:border-slate-800 bg-white dark:bg-slate-900 px-4 sm:px-6 flex items-center justify-between shadow-xs transition-colors duration-150">
      {/* Left: Mobile Toggle & Breadcrumb */}
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          className="text-[#667085] hover:text-[#1F2933] dark:text-slate-400 dark:hover:text-slate-100 lg:hidden p-1.5"
          aria-label="Toggle menu"
        >
          <Menu className="w-5 h-5" />
        </Button>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-[#667085] dark:text-slate-400 hidden sm:inline font-medium">TrustGuard</span>
          <span className="text-[#D5DDE5] dark:text-slate-600 hidden sm:inline">/</span>
          <span className="text-[#17324D] dark:text-slate-100 font-semibold text-sm">{currentRouteName}</span>
        </div>
      </div>

      {/* Right: System Status, Reset Demo, Theme Toggle & User Profile */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* System Status: Secure */}
        <div className="hidden sm:flex items-center gap-2 bg-[#ECFDF3] dark:bg-emerald-950/40 border border-[#D1FADF] dark:border-emerald-800/60 px-3 py-1.5 rounded-md text-xs">
          <span className="w-2 h-2 rounded-full bg-[#2E7D5B] dark:bg-emerald-400 shrink-0" />
          <span className="font-semibold text-[#2E7D5B] dark:text-emerald-400">System status: Secure</span>
        </div>

        {/* Quick Reset Demo Action */}
        <button
          type="button"
          onClick={resetDemoState}
          title="Reset Demo State"
          aria-label="Reset Demo State"
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-[#475467] dark:text-slate-400 hover:text-[#17324D] dark:hover:text-slate-100 bg-[#F1F4F7] dark:bg-slate-800 hover:bg-[#E4E7EC] dark:hover:bg-slate-700 border border-[#D5DDE5] dark:border-slate-700 transition-colors cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Reset Demo</span>
        </button>

        {/* VISIBLE LIGHT / DARK THEME TOGGLE CONTROL */}
        <div 
          className="flex items-center bg-[#F1F4F7] dark:bg-slate-800 p-0.5 rounded-lg border border-[#D5DDE5] dark:border-slate-700 shadow-xs"
          role="radiogroup" 
          aria-label="Theme toggle"
        >
          {/* Light Mode Button */}
          <button
            type="button"
            role="radio"
            aria-checked={!isDark}
            title="Switch to Light Theme"
            onClick={() => setTheme('light')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer select-none focus:outline-none focus-visible:ring-2 focus-visible:ring-[#17324D] dark:focus-visible:ring-cyan-400 ${
              !isDark
                ? 'bg-white text-[#17324D] shadow-xs border border-[#C7D0DA]'
                : 'text-[#667085] hover:text-[#1F2933] dark:text-slate-400 dark:hover:text-slate-100'
            }`}
          >
            <Sun className={`w-3.5 h-3.5 ${!isDark ? 'text-amber-600' : 'text-slate-400'}`} />
            <span className="hidden xs:inline">Light</span>
          </button>

          {/* Dark Mode Button */}
          <button
            type="button"
            role="radio"
            aria-checked={isDark}
            title="Switch to Dark Theme"
            onClick={() => setTheme('dark')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer select-none focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${
              isDark
                ? 'bg-slate-900 text-cyan-300 shadow-xs border border-slate-700'
                : 'text-[#667085] hover:text-[#1F2933] dark:text-slate-400 dark:hover:text-slate-100'
            }`}
          >
            <Moon className={`w-3.5 h-3.5 ${isDark ? 'text-cyan-300' : 'text-slate-500'}`} />
            <span className="hidden xs:inline">Dark</span>
          </button>
        </div>

        {/* User / Profile */}
        <div className="flex items-center gap-2.5 pl-2 sm:pl-3 border-l border-[#D5DDE5] dark:border-slate-800">
          <div className="w-8 h-8 rounded-full bg-[#F0F5F9] dark:bg-slate-800 border border-[#D5DDE5] dark:border-slate-700 flex items-center justify-center text-[#17324D] dark:text-slate-200 text-xs font-semibold">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden md:flex flex-col text-left">
            <span className="text-xs font-semibold text-[#1F2933] dark:text-slate-100 leading-tight">
              Exam Administrator
            </span>
            <span className="text-[11px] text-[#667085] dark:text-slate-400 leading-tight">
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
