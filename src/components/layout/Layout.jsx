import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

export function Layout() {
  return (
    <div className="min-h-screen flex bg-[#F5F7FA] text-[#1F2933] antialiased font-sans">
      {/* Left Navigation Sidebar */}
      <Sidebar />

      {/* Main App Viewport */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar />

        <main className="flex-1 overflow-y-auto bg-[#F5F7FA]">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
