import React, { useState } from 'react';
import { 
  Building2, 
  ShieldCheck, 
  Lock, 
  Unlock, 
  Clock, 
  CheckCircle2, 
  AlertCircle, 
  FileText, 
  Play, 
  XCircle, 
  RotateCcw,
  Check
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

const PAPERS = [
  { id: 'JEE-MOCK-001', name: 'Engineering Entrance Examination' },
  { id: 'NEET-MOCK-002', name: 'Medical Entrance Examination' },
  { id: 'DEMO-004', name: 'TrustGuard Demonstration' },
];

export function ExamCenterPage() {
  const { 
    paper, 
    isQuorumAchieved, 
    completeFinalApproval, 
    openSecurePaperSession, 
    closeSecurePaperSession, 
    resetDemoState 
  } = useTrustGuard();

  const [selectedPaperId, setSelectedPaperId] = useState('JEE-MOCK-001');
  const selectedPaper = PAPERS.find((p) => p.id === selectedPaperId) || PAPERS[0];

  const sessionState = paper.examAccess === 'Active' ? 'active' : paper.examAccess === 'Closed' ? 'closed' : 'idle';

  const handleSimulateAuthorization = () => {
    completeFinalApproval();
  };

  const handleOpenSecurePaper = () => {
    if (!isQuorumAchieved) return;
    openSecurePaperSession();
  };

  const handleCloseSession = () => {
    closeSecurePaperSession();
  };

  const handleReset = () => {
    resetDemoState();
  };

  // Compute Current State label
  const getExamWindowState = () => {
    if (sessionState === 'closed') return 'Closed';
    if (sessionState === 'active') return 'Active';
    if (isQuorumAchieved) return 'Ready';
    return 'Not Active';
  };

  return (
    <PageContainer
      title="Exam Center"
      subtitle="View and manage authorized access to examination papers."
      action={
        <div className="flex items-center gap-2">
          {sessionState === 'active' ? (
            <Badge variant="success" size="md" dot>
              Session Active
            </Badge>
          ) : sessionState === 'closed' ? (
            <Badge variant="default" size="md">
              Session Closed
            </Badge>
          ) : isQuorumAchieved ? (
            <Badge variant="success" size="md" dot>
              Access Authorized
            </Badge>
          ) : (
            <Badge variant="default" size="md">
              Access Locked
            </Badge>
          )}
        </div>
      }
    >
      {/* SECTION 1 — PAPER SELECTION & CONTROLS */}
      <Card className="p-4 bg-white border border-[#C7D0DA] space-y-4 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[#F0F5F9] border border-[#D5DDE5] text-[#17324D]">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-[#17324D]">
                  {selectedPaper.id}
                </span>
                <Badge variant="success" size="sm" dot>
                  Protected
                </Badge>
              </div>
              <h2 className="text-sm font-bold text-[#1F2933] mt-0.5">
                {selectedPaper.name}
              </h2>
            </div>
          </div>

          {/* Paper selector dropdown */}
          <div className="flex items-center gap-2">
            <label htmlFor="paper-select" className="text-xs text-[#667085] font-semibold whitespace-nowrap">
              Select Paper:
            </label>
            <select
              id="paper-select"
              value={selectedPaperId}
              onChange={(e) => {
                setSelectedPaperId(e.target.value);
              }}
              className="bg-white text-[#1F2933] border border-[#C7D0DA] text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-[#17324D]/10 focus:border-[#17324D] cursor-pointer"
            >
              {PAPERS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.id} ({p.name})
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* SECTION 6 — COMPACT SECURITY LIFECYCLE */}
      <Card
        className="p-4 bg-white border border-[#C7D0DA] space-y-3 shadow-xs"
        header={
          <div className="flex items-center justify-between w-full">
            <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider">
              Examination Security Lifecycle
            </h3>
            <span className="text-[11px] text-[#667085] font-mono font-semibold">
              Stage {sessionState === 'closed' ? '4 of 4' : sessionState === 'active' ? '3 of 4' : isQuorumAchieved ? '2 of 4' : '1 of 4'}
            </span>
          </div>
        }
      >
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
          {/* Step 1: Protected */}
          <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between">
            <span className="font-semibold text-[#1F2933]">Protected</span>
            <div className="flex items-center gap-1 text-[#2E7D5B] font-bold text-xs">
              <Check className="w-3.5 h-3.5" />
            </div>
          </div>

          {/* Step 2: Authorized */}
          <div className={`p-2.5 rounded-lg border flex items-center justify-between ${
            isQuorumAchieved ? 'bg-[#F1F4F7] border-[#D5DDE5]' : 'bg-[#FFFAEB] border-[#FEDF89]'
          }`}>
            <span className="font-semibold text-[#1F2933]">Authorized</span>
            {isQuorumAchieved ? (
              <div className="flex items-center gap-1 text-[#2E7D5B] font-bold text-xs">
                <Check className="w-3.5 h-3.5" />
              </div>
            ) : (
              <span className="text-[#B7791F] text-xs font-mono font-semibold">{paper.currentApprovals} / {paper.requiredApprovals}</span>
            )}
          </div>

          {/* Step 3: Access Active */}
          <div className={`p-2.5 rounded-lg border flex items-center justify-between ${
            sessionState === 'active' 
              ? 'bg-[#ECFDF3] border-[#D1FADF] text-[#2E7D5B]' 
              : 'bg-[#F1F4F7] border-[#D5DDE5] text-[#667085]'
          }`}>
            <span className="font-semibold">Access Active</span>
            <span className="text-xs font-mono font-bold">
              {sessionState === 'active' ? '● Active' : '○'}
            </span>
          </div>

          {/* Step 4: Session Closed */}
          <div className={`p-2.5 rounded-lg border flex items-center justify-between ${
            sessionState === 'closed' 
              ? 'bg-[#F1F4F7] border-[#D5DDE5] text-[#344054]' 
              : 'bg-[#F1F4F7] border-[#D5DDE5] text-[#667085]'
          }`}>
            <span className="font-semibold">Session Closed</span>
            <span className="text-xs font-mono font-bold">
              {sessionState === 'closed' ? '✓ Closed' : '○'}
            </span>
          </div>
        </div>
      </Card>

      {/* SECTION 2 & 3 — ACCESS STATUS & EXAM WINDOW (TWO COLUMNS) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* SECTION 2 — ACCESS STATUS */}
        <Card className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs">
          <div className="flex items-center justify-between pb-3 border-b border-[#D5DDE5]">
            <span className="text-xs font-bold uppercase text-[#667085] tracking-wider">
              Access Status
            </span>
            {isQuorumAchieved ? (
              <Badge variant="success" size="md">
                AUTHORIZED
              </Badge>
            ) : (
              <Badge variant="default" size="md">
                LOCKED
              </Badge>
            )}
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between items-center">
              <span className="text-[#667085] font-medium">Authorization:</span>
              <span className={`font-mono font-bold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
                {paper.currentApprovals} / {paper.requiredApprovals} approvals
              </span>
            </div>

            <div className="flex justify-between items-start gap-2">
              <span className="text-[#667085] font-medium shrink-0">Reason:</span>
              <span className="text-[#1F2933] font-semibold text-right">
                {isQuorumAchieved
                  ? 'Required authorization has been completed.'
                  : 'Required quorum has not been reached.'}
              </span>
            </div>
          </div>

          {/* Quick Demo Toggle for Authorization */}
          {!isQuorumAchieved && sessionState === 'idle' && (
            <div className="pt-2 border-t border-[#D5DDE5] flex items-center justify-between">
              <span className="text-[11px] text-[#667085]">
                Frontend demonstration:
              </span>
              <Button
                variant="outline"
                size="sm"
                className="text-xs"
                onClick={handleSimulateAuthorization}
              >
                Simulate Quorum (3/3)
              </Button>
            </div>
          )}
        </Card>

        {/* SECTION 3 — EXAM WINDOW */}
        <Card className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs">
          <div className="flex items-center justify-between pb-3 border-b border-[#D5DDE5]">
            <span className="text-xs font-bold uppercase text-[#667085] tracking-wider">
              Exam Window
            </span>
            <span className="font-mono text-xs font-bold text-[#17324D]">
              {paper.examWindow}
            </span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between items-center">
              <span className="text-[#667085] font-medium">Current State:</span>
              <span className={`font-semibold ${
                sessionState === 'active' 
                  ? 'text-[#2E7D5B]' 
                  : sessionState === 'closed' 
                  ? 'text-[#667085]' 
                  : isQuorumAchieved 
                  ? 'text-[#17324D]' 
                  : 'text-[#667085]'
              }`}>
                {getExamWindowState()}
              </span>
            </div>

            <div className="flex justify-between items-start gap-2">
              <span className="text-[#667085] font-medium shrink-0">Window Schedule:</span>
              <span className="text-[#344054] text-right">
                Designated examination release period
              </span>
            </div>
          </div>

          {isQuorumAchieved && sessionState === 'idle' && (
            <div className="pt-2 border-t border-[#D5DDE5] flex items-center justify-between">
              <span className="text-[11px] text-[#2E7D5B] font-semibold">
                Authorization satisfied
              </span>
              <span className="text-[11px] text-[#667085]">
                Ready for release
              </span>
            </div>
          )}
        </Card>
      </div>

      {/* SECTION 4 & 5 — ACCESS ACTION & SECURE EXAM SESSION AREA */}
      <Card className="p-6 bg-white border border-[#C7D0DA] space-y-4 shadow-xs">
        {sessionState === 'idle' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#D5DDE5]">
              <div>
                <h3 className="text-sm font-bold text-[#17324D]">
                  Paper Access Gate
                </h3>
                <p className="text-xs text-[#667085] mt-0.5">
                  {isQuorumAchieved
                    ? 'Quorum reached. You may now initialize the active secure session.'
                    : 'Access button remains locked until 3 of 3 officer approvals are submitted.'}
                </p>
              </div>

              {/* Action Button */}
              {isQuorumAchieved ? (
                <Button
                  variant="primary"
                  size="md"
                  icon={Unlock}
                  onClick={handleOpenSecurePaper}
                  className="font-semibold"
                >
                  Open Secure Paper
                </Button>
              ) : (
                <Button
                  variant="secondary"
                  size="md"
                  icon={Lock}
                  disabled
                  className="opacity-60 cursor-not-allowed"
                >
                  Access Unavailable
                </Button>
              )}
            </div>

            {!isQuorumAchieved && (
              <div className="p-3.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-xs text-[#667085] flex items-start gap-2.5">
                <Lock className="w-4 h-4 text-[#667085] shrink-0 mt-0.5" />
                <span>
                  Examination question paper content is fragmented across isolated storage nodes and cannot be assembled without complete 3/3 quorum authorization.
                </span>
              </div>
            )}
          </div>
        )}

        {/* ACTIVE SECURE EXAM SESSION (SECTION 4) */}
        {sessionState === 'active' && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-[#ECFDF3] border border-[#D1FADF] flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-white text-[#2E7D5B] border border-[#D1FADF] shrink-0 shadow-xs">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-[#2E7D5B] tracking-wider uppercase">
                      SECURE EXAM ACCESS
                    </span>
                    <Badge variant="success" size="sm" dot>
                      Active
                    </Badge>
                  </div>
                  <h3 className="text-sm font-bold text-[#17324D] mt-0.5">
                    Paper: <span className="font-mono">{selectedPaper.id}</span>
                  </h3>
                  <div className="flex items-center gap-3 text-xs text-[#344054] mt-1 flex-wrap">
                    <span>Access Status: <strong className="text-[#2E7D5B]">Active</strong></span>
                    <span>•</span>
                    <span>Exam Window: <strong className="font-mono text-[#17324D]">{paper.examWindow}</strong></span>
                  </div>
                </div>
              </div>

              {/* SECTION 5 — CLOSE SESSION BUTTON */}
              <Button
                variant="danger"
                size="sm"
                icon={XCircle}
                onClick={handleCloseSession}
                className="shrink-0 font-semibold"
              >
                Close Session
              </Button>
            </div>

            <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-xs text-[#344054]">
              <strong>Notice:</strong> The authorized exam-paper access window is currently active.
            </div>

            {/* Placeholder for Question Paper Content */}
            <div className="p-8 rounded-xl bg-[#F1F4F7] border border-dashed border-[#C7D0DA] text-center space-y-2">
              <FileText className="w-8 h-8 text-[#17324D] mx-auto" />
              <p className="text-xs font-semibold text-[#1F2933]">
                Protected examination content is ready for review in verified session.
              </p>
              <p className="text-[11px] text-[#667085]">
                Rendered exclusively within the verified exam terminal memory.
              </p>
            </div>
          </div>
        )}

        {/* SESSION CLOSED STATE (SECTION 5) */}
        {sessionState === 'closed' && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-white border border-[#D5DDE5] text-[#667085]">
                  <Lock className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-[#1F2933]">
                    Exam-paper access session closed.
                  </h3>
                  <p className="text-xs text-[#667085] mt-0.5">
                    Terminal memory cleared. Access keys discarded from runtime.
                  </p>
                </div>
              </div>

              <Button
                variant="outline"
                size="sm"
                icon={RotateCcw}
                onClick={handleReset}
                className="shrink-0 text-xs"
              >
                Reset Demo
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* SECTION 7 — RECENT ACTIVITY */}
      <Card
        className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs"
        header={
          <div className="flex items-center justify-between w-full">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-[#667085]" />
              <h3 className="text-sm font-bold text-[#17324D]">
                Recent Activity
              </h3>
            </div>
            <span className="text-[10px] text-[#667085] font-mono">
              Exam Center Log
            </span>
          </div>
        }
      >
        <div className="space-y-2">
          {/* 09:42 Paper protected */}
          <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#17324D] shrink-0" />
              <span className="text-[#1F2933] font-medium">Paper protected</span>
            </div>
            <span className="text-[11px] text-[#667085] font-mono">09:42</span>
          </div>

          {/* 09:44 Final authorization completed */}
          {isQuorumAchieved && (
            <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-[#2E7D5B] shrink-0" />
                <span className="text-[#1F2933] font-medium">Final authorization completed</span>
              </div>
              <span className="text-[11px] text-[#667085] font-mono">09:44</span>
            </div>
          )}

          {/* 09:55 Exam access window opened */}
          {(sessionState === 'active' || sessionState === 'closed') && (
            <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-[#2E7D5B] shrink-0" />
                <span className="text-[#1F2933] font-medium">Exam access window opened</span>
              </div>
              <span className="text-[11px] text-[#667085] font-mono">09:55</span>
            </div>
          )}

          {/* 12:00 Exam access session closed */}
          {sessionState === 'closed' && (
            <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-[#667085] shrink-0" />
                <span className="text-[#1F2933] font-medium">Exam access session closed</span>
              </div>
              <span className="text-[11px] text-[#667085] font-mono">12:00</span>
            </div>
          )}
        </div>
      </Card>
    </PageContainer>
  );
}
