import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { ShieldCheck, Clock, FileText, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTrustGuard } from '../hooks/useTrustGuard';

export function StudentExamPortalPage() {
  const { examId } = useParams();
  const { user } = useAuth();
  const { paper, streamContent } = useTrustGuard();

  const [timeRemaining, setTimeRemaining] = useState(null);

  // Simple countdown timer (demo — counts down from 180 min)
  useEffect(() => {
    if (paper?.examAccess === 'Active') {
      let remaining = 180 * 60; // 3 hours in seconds
      setTimeRemaining(remaining);
      const interval = setInterval(() => {
        remaining -= 1;
        setTimeRemaining(remaining);
        if (remaining <= 0) clearInterval(interval);
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [paper?.examAccess]);

  const formatTime = (secs) => {
    if (secs == null) return '--:--:--';
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header bar */}
      <header className="sticky top-0 z-50 bg-white border-b border-slate-200 px-6 py-3 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-6 h-6 text-blue-600" />
          <div>
            <h1 className="text-sm font-bold text-slate-800">TrustGuard Exam Portal</h1>
            <p className="text-xs text-slate-500">Secure Examination Session</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-xs">
            <Clock className="w-4 h-4 text-amber-600" />
            <span className="font-mono font-semibold text-slate-700">{formatTime(timeRemaining)}</span>
          </div>
          <span className="text-xs text-slate-500">
            {user?.username || 'Student'}
          </span>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto p-6">
        {paper?.examAccess === 'Active' || streamContent ? (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-8">
            <div className="flex items-center gap-2 mb-6">
              <FileText className="w-5 h-5 text-blue-600" />
              <h2 className="text-lg font-semibold text-slate-800">Examination Paper</h2>
            </div>
            <div className="prose max-w-none text-sm text-slate-700 whitespace-pre-wrap">
              {streamContent || 'Exam content is being securely streamed...'}
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <div className="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center mb-4">
              <AlertCircle className="w-8 h-8 text-amber-600" />
            </div>
            <h2 className="text-lg font-semibold text-slate-800 mb-2">Exam Not Active</h2>
            <p className="text-sm text-slate-500 max-w-sm">
              The examination session has not been opened yet. Please wait for authorization from the exam guardians.
            </p>
            <p className="text-xs text-slate-400 mt-4">
              Exam ID: {examId || paper?.id || 'Not specified'}
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
