import React from 'react';

export function AmbientBubbles() {
  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none" aria-hidden="true">
      {/* Bubble 1: Top-Left Soft Blue */}
      <div 
        className="absolute -top-12 left-10 w-96 h-96 rounded-full bg-[#EAF2F8]/70 blur-3xl animate-bubble-slow"
      />

      {/* Bubble 2: Top-Right Soft Green */}
      <div 
        className="absolute top-20 -right-16 w-80 h-80 rounded-full bg-[#EAF5F0]/70 blur-3xl animate-bubble-reverse"
      />

      {/* Bubble 3: Center-Left Soft Teal */}
      <div 
        className="absolute top-1/3 -left-20 w-84 h-84 rounded-full bg-[#E1F3F5]/60 blur-3xl animate-bubble-drift"
      />

      {/* Bubble 4: Bottom-Right Soft Amber */}
      <div 
        className="absolute bottom-20 right-1/4 w-72 h-72 rounded-full bg-[#FAF3E7]/60 blur-3xl animate-bubble-slow"
      />

      {/* Bubble 5: Bottom-Left Soft Blue */}
      <div 
        className="absolute -bottom-16 left-1/3 w-96 h-96 rounded-full bg-[#EAF2F8]/60 blur-3xl animate-bubble-reverse"
      />
    </div>
  );
}
