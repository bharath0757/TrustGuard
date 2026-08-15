import React, { useState } from 'react';
import { 
  CheckSquare, 
  CheckCircle2, 
  Clock, 
  Lock, 
  ShieldCheck, 
  UserCheck, 
  FileText, 
  RotateCcw,
  AlertCircle
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

export function ApprovalsPage() {
  const { 
    paper, 
    officers, 
    isQuorumAchieved, 
    completeFinalApproval, 
    resetDemoState 
  } = useTrustGuard();

  const [showNotification, setShowNotification] = useState(false);

  const handleApprove = () => {
    if (isQuorumAchieved) return;
    completeFinalApproval();
    setShowNotification(true);
  };

  const handleReset = () => {
    resetDemoState();
    setShowNotification(false);
  };

  const currentApprovals = paper.currentApprovals;
  const progressPercent = (currentApprovals / paper.requiredApprovals) * 100;

  const timelineEvents = [
    { time: '09:44', event: 'Officer A approved' },
    { time: '09:44', event: 'Officer B approved' },
    ...(isQuorumAchieved
      ? [
          { time: '09:45', event: 'Officer C approved' },
          { time: '09:45', event: 'Quorum achieved' },
          { time: '09:45', event: 'Final approval received' },
        ]
      : [{ time: '09:45', event: 'Awaiting final approval' }]),
  ];

  return (
    <PageContainer
      title="Approvals"
      subtitle="Review authorization requests for protected examination papers."
      action={
        <Badge variant={isQuorumAchieved ? 'success' : 'warning'} size="md">
          {isQuorumAchieved ? 'Quorum Achieved (3/3)' : 'Awaiting Approval (2/3)'}
        </Badge>
      }
    >
      {/* SUCCESS NOTIFICATION */}
      {showNotification && (
        <div className="p-4 rounded-xl bg-[#ECFDF3] border border-[#D1FADF] text-[#2E7D5B] flex items-start justify-between gap-3 text-xs shadow-xs">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-[#2E7D5B] shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-[#17324D] block text-sm">
                Approval Recorded — Quorum Achieved
              </span>
              <p className="text-[#2E7D5B] mt-0.5 font-medium">
                Officer C has signed the authorization request. Quorum requirement (3 of 3) is satisfied for <strong>{paper.id}</strong>. Access status is now Authorized.
              </p>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="text-[#2E7D5B] hover:text-[#17324D] text-xs p-1"
            onClick={() => setShowNotification(false)}
          >
            Dismiss
          </Button>
        </div>
      )}

      {/* SECTION 1 — SELECTED PAPER & SECTION 2 — AUTHORIZATION PROGRESS */}
      <Card className="p-5 bg-white border border-[#C7D0DA] space-y-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#D5DDE5]">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-lg bg-[#F0F5F9] border border-[#D5DDE5] text-[#17324D] shrink-0">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-xs font-bold text-[#17324D]">
                  {paper.id}
                </span>
                <Badge variant="success" size="sm" dot>
                  Protected
                </Badge>
              </div>
              <h2 className="text-base font-bold text-[#17324D] mt-0.5">
                {paper.name}
              </h2>
            </div>
          </div>

          {/* Key Metric Highlights */}
          <div className="grid grid-cols-3 gap-3 self-start sm:self-center text-xs">
            <div className="p-2 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
              <span className="text-[10px] text-[#667085] block font-medium">Required</span>
              <span className="font-bold text-[#1F2933] font-mono">{paper.requiredApprovals} Approvals</span>
            </div>
            <div className="p-2 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
              <span className="text-[10px] text-[#667085] block font-medium">Current</span>
              <span className={`font-bold font-mono ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
                {currentApprovals} / {paper.requiredApprovals}
              </span>
            </div>
            <div className="p-2 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
              <span className="text-[10px] text-[#667085] block font-medium">Access</span>
              <span className={`font-bold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#667085]'}`}>
                {isQuorumAchieved ? 'Authorized' : 'Locked'}
              </span>
            </div>
          </div>
        </div>

        {/* SECTION 2 — AUTHORIZATION PROGRESS BAR */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-[#1F2933]">
              {currentApprovals} / {paper.requiredApprovals} approvals
            </span>
            <span className="text-[#667085] font-mono text-[11px]">
              {Math.round(progressPercent)}% Complete
            </span>
          </div>

          <div className="w-full h-2 rounded-full bg-[#F1F4F7] overflow-hidden border border-[#D5DDE5]">
            <div
              className={`h-full transition-all duration-300 ${
                isQuorumAchieved ? 'bg-[#2E7D5B]' : 'bg-[#B7791F]'
              }`}
              style={{ width: `${progressPercent}%` }}
            />
          </div>

          <p className="text-xs text-[#667085]">
            {isQuorumAchieved
              ? 'Quorum achieved. Access authorization is ready.'
              : 'One approval is still required.'}
          </p>
        </div>
      </Card>

      {/* SECTION 3 — OFFICER APPROVAL CARDS & SECTION 4 — APPROVAL ACTION */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-[#17324D]" />
            Officer Approvals
          </h3>
          <span className="text-xs text-[#667085]">
            {currentApprovals} of {paper.requiredApprovals} Authorized Signatures Recorded
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Card 1: Officer A */}
          <Card className="p-4 bg-white border border-[#C7D0DA] space-y-3 flex flex-col justify-between shadow-xs">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-[#1F2933]">{officers.officerA.name}</span>
                <Badge variant="success" size="sm" dot>
                  Approved
                </Badge>
              </div>
              <p className="text-xs text-[#667085]">
                Role: <span className="text-[#344054] font-medium">{officers.officerA.role}</span>
              </p>
            </div>
            <div className="pt-2 border-t border-[#D5DDE5] text-[11px] text-[#667085] font-mono flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-[#667085]" />
              <span>Signed at {officers.officerA.time}</span>
            </div>
          </Card>

          {/* Card 2: Officer B */}
          <Card className="p-4 bg-white border border-[#C7D0DA] space-y-3 flex flex-col justify-between shadow-xs">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-[#1F2933]">{officers.officerB.name}</span>
                <Badge variant="success" size="sm" dot>
                  Approved
                </Badge>
              </div>
              <p className="text-xs text-[#667085]">
                Role: <span className="text-[#344054] font-medium">{officers.officerB.role}</span>
              </p>
            </div>
            <div className="pt-2 border-t border-[#D5DDE5] text-[11px] text-[#667085] font-mono flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-[#667085]" />
              <span>Signed at {officers.officerB.time}</span>
            </div>
          </Card>

          {/* Card 3: Officer C (Interactive Action) */}
          <Card className={`p-4 border transition-colors flex flex-col justify-between space-y-3 shadow-xs ${
            isQuorumAchieved 
              ? 'bg-white border-[#C7D0DA]' 
              : 'bg-[#FFFAEB] border-[#FEDF89]'
          }`}>
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-[#1F2933]">{officers.officerC.name}</span>
                {isQuorumAchieved ? (
                  <Badge variant="success" size="sm" dot>
                    Approved
                  </Badge>
                ) : (
                  <Badge variant="warning" size="sm" dot>
                    Pending
                  </Badge>
                )}
              </div>
              <p className="text-xs text-[#667085]">
                Role: <span className="text-[#344054] font-medium">{officers.officerC.role}</span>
              </p>
            </div>

            {/* Action Area */}
            <div className="pt-2 border-t border-[#D5DDE5]">
              {!isQuorumAchieved ? (
                <div className="space-y-2">
                  <Button
                    variant="primary"
                    size="sm"
                    className="w-full justify-center font-semibold"
                    icon={CheckSquare}
                    onClick={handleApprove}
                  >
                    Approve
                  </Button>
                  <span className="text-[10px] text-[#B7791F] text-center block font-medium">
                    Action required to complete quorum
                  </span>
                </div>
              ) : (
                <div className="flex items-center justify-between text-[11px] text-[#667085] font-mono">
                  <span className="flex items-center gap-1 text-[#2E7D5B] font-semibold">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Signed at {officers.officerC.time || '09:45'}
                  </span>
                  <button
                    type="button"
                    onClick={handleReset}
                    className="text-[10px] text-[#667085] hover:text-[#1F2933] underline cursor-pointer"
                  >
                    Reset
                  </button>
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>

      {/* TWO COLUMNS: SECTION 5 (ACCESS STATUS) & SECTION 6 (RECENT APPROVAL ACTIVITY) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* SECTION 5 — ACCESS STATUS */}
        <Card
          className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
          header={
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-[#667085]" />
              <h3 className="text-sm font-bold text-[#17324D]">
                Access Status
              </h3>
            </div>
          }
        >
          <div className="p-4 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[#667085] font-medium">Current State:</span>
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

            <div className="pt-2 border-t border-[#D5DDE5]">
              <span className="text-[#667085] font-semibold block text-[11px] mb-1">
                Access Policy Reason:
              </span>
              <p className="text-[#1F2933] leading-relaxed font-semibold">
                {isQuorumAchieved
                  ? 'Required quorum achieved.'
                  : 'Required quorum has not been reached.'}
              </p>
            </div>
          </div>

          <p className="text-xs text-[#667085] leading-relaxed">
            {isQuorumAchieved
              ? 'All 3 designated officers have provided valid signatures. Examination question paper access is authorized for distribution to certified examination terminals.'
              : 'Paper remains locked in isolated secure storage until all 3 officers independently approve the authorization request.'}
          </p>
        </Card>

        {/* SECTION 6 — RECENT APPROVAL ACTIVITY */}
        <Card
          className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs"
          header={
            <div className="flex items-center justify-between w-full">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#667085]" />
                <h3 className="text-sm font-bold text-[#17324D]">
                  Recent Approval Activity
                </h3>
              </div>
              <span className="text-[10px] text-[#667085] font-mono">
                Log History
              </span>
            </div>
          }
        >
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {timelineEvents.map((item, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-2.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#17324D] shrink-0" />
                  <span className="text-[#1F2933] font-medium">
                    {item.event}
                  </span>
                </div>
                <span className="text-[11px] text-[#667085] font-mono shrink-0 ml-2">
                  {item.time}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </PageContainer>
  );
}
