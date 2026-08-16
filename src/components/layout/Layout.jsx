import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { AmbientBubbles } from '../ui';

export function Layout() {
  return (
    <div className="relative min-h-screen flex bg-[#F5F7FA] text-[#182230] antialiased font-sans">
      {/* Background Ambient Bubbles */}
      <AmbientBubbles />

      {/* Left Navigation Sidebar */}
      <Sidebar />

      {/* Main App Viewport */}
      <div className="relative z-10 flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar />

        <main className="flex-1 overflow-y-auto bg-transparent">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

