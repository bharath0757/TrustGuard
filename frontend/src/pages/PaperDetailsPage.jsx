import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, 
  CheckCircle2, 
  Clock, 
  Lock, 
  ShieldCheck, 
  FileText, 
  Layers, 
  UserCheck, 
  Calendar,
  CheckSquare,
  AlertCircle,
  Play,
  RotateCcw
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

export function PaperDetailsPage() {
  const { paperId } = useParams();
  const navigate = useNavigate();
  const { 
    paper, 
    officers, 
    isQuorumAchieved, 
    completeFinalApproval, 
    resetDemoState,
    auditEvents
  } = useTrustGuard();

  const currentPaperId = paperId || paper.id;
  const [showNotification, setShowNotification] = useState(false);

  const handleSimulateApproval = () => {
    if (isQuorumAchieved) return;
    completeFinalApproval();
    setShowNotification(true);
  };

  const handleResetDemo = () => {
    resetDemoState();
    setShowNotification(false);
  };

  // Build timeline based on state and audit logs
  const timelineEvents = [
    { time: '09:42', event: 'Paper registered' },
    { time: '09:42', event: 'Encryption completed' },
    { time: '09:43', event: 'Paper fragmented' },
    { time: '09:43', event: 'Fragments distributed' },
    { time: '09:44', event: 'Officer A approved' },
    { time: '09:44', event: 'Officer B approved' },
    ...(isQuorumAchieved
      ? [
          { time: '09:45', event: 'Final approval received (Officer C)' },
          { time: '09:45', event: 'Decryption authorized for scheduled exam window' },
        ]
      : [{ time: '09:45', event: 'Awaiting final approval' }]),
  ];

  return (
    <PageContainer
      title={currentPaperId}
      subtitle="Engineering Entrance Examination"
      action={
        <div className="flex items-center gap-3">
          <Badge variant="success" size="md" dot>
            PROTECTED
          </Badge>
          <Button
            variant="outline"
            size="sm"
            icon={ArrowLeft}
            onClick={() => navigate('/papers')}
          >
            Back to Question Papers
          </Button>
        </div>
      }
    >
      {/* SUCCESS NOTIFICATION */}
      {showNotification && (
        <div className="p-4 rounded-xl bg-[#ECFDF3] border border-[#D1FADF] text-[#2E7D5B] flex items-start justify-between gap-3 text-xs shadow-xs">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-[#2E7D5B] shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-[#17324D] block text-sm">
                Quorum Reached — Authorization Complete
              </span>
              <p className="text-[#2E7D5B] mt-0.5 font-medium">
                Officer C has signed. Required 3 of 3 approvals collected. Question paper is authorized for scheduled examination release.
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

      {/* SECTION 1 — SECURITY LIFECYCLE */}
      <Card
        className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
        header={
          <div className="flex items-center justify-between w-full">
            <div>
              <h2 className="text-sm font-bold text-[#17324D]">
                Security Lifecycle
              </h2>
              <p className="text-xs text-[#667085] mt-0.5">
                End-to-end protective status of this examination question paper
              </p>
            </div>
            <Badge variant={isQuorumAchieved ? 'success' : 'warning'} size="sm">
              {isQuorumAchieved ? 'Lifecycle Complete' : 'Awaiting Authorization'}
            </Badge>
          </div>
        }
      >
        {/* Horizontal Lifecycle (Desktop) & Stacked (Mobile) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2.5">
          {/* Step 1: Paper Created */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-[#667085] font-mono block mb-1">Step 1</span>
              <h3 className="text-xs font-semibold text-[#1F2933]">Paper Created</h3>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5 text-[11px] text-[#2E7D5B] font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Complete</span>
            </div>
          </div>

          {/* Step 2: Encryption */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-[#667085] font-mono block mb-1">Step 2</span>
              <h3 className="text-xs font-semibold text-[#1F2933]">Encryption</h3>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5 text-[11px] text-[#2E7D5B] font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Complete</span>
            </div>
          </div>

          {/* Step 3: Fragmentation */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-[#667085] font-mono block mb-1">Step 3</span>
              <h3 className="text-xs font-semibold text-[#1F2933]">Fragmentation</h3>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5 text-[11px] text-[#2E7D5B] font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Complete</span>
            </div>
          </div>

          {/* Step 4: Distribution */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-[#667085] font-mono block mb-1">Step 4</span>
              <h3 className="text-xs font-semibold text-[#1F2933]">Distribution</h3>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5 text-[11px] text-[#2E7D5B] font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Complete</span>
            </div>
          </div>

          {/* Step 5: Authorization */}
          <div className={`p-3 rounded-lg border flex flex-col justify-between ${
            isQuorumAchieved ? 'bg-[#F1F4F7] border-[#D5DDE5]' : 'bg-[#FFFAEB] border-[#FEDF89]'
          }`}>
            <div>
              <span className="text-[10px] text-[#667085] font-mono block mb-1">Step 5</span>
              <h3 className="text-xs font-semibold text-[#1F2933]">Authorization</h3>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5 text-[11px] font-medium">
              {isQuorumAchieved ? (
                <span className="text-[#2E7D5B] flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Approved (3 / 3)
                </span>
              ) : (
                <span className="text-[#B7791F] flex items-center gap-1 font-semibold">
                  <Clock className="w-3.5 h-3.5" />
                  Pending (2 / 3)
                </span>
              )}
            </div>
          </div>

          {/* Step 6: Decryption */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-[#667085] font-mono block mb-1">Step 6</span>
              <h3 className="text-xs font-semibold text-[#1F2933]">Decryption</h3>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5 text-[11px] font-medium">
              {isQuorumAchieved ? (
                <span className="text-[#2E7D5B] flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Authorized
                </span>
              ) : (
                <span className="text-[#667085] flex items-center gap-1">
                  <Lock className="w-3.5 h-3.5 text-[#667085]" />
                  Locked
                </span>
              )}
            </div>
          </div>

          {/* Step 7: Exam Access */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-[#667085] font-mono block mb-1">Step 7</span>
              <h3 className="text-xs font-semibold text-[#1F2933]">Exam Access</h3>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5 text-[11px] font-medium">
              {isQuorumAchieved ? (
                <span className="text-[#2E7D5B] flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Ready
                </span>
              ) : (
                <span className="text-[#667085] flex items-center gap-1">
                  <Lock className="w-3.5 h-3.5 text-[#667085]" />
                  Locked
                </span>
              )}
            </div>
          </div>
        </div>
      </Card>

      {/* SECTION 2 — SECURITY SUMMARY */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <span className="text-xs font-semibold text-[#667085] block mb-1">Encryption</span>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
            <span className="text-sm font-bold text-[#2E7D5B]">Complete</span>
          </div>
        </Card>

        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <span className="text-xs font-semibold text-[#667085] block mb-1">Fragments</span>
          <span className="text-sm font-bold text-[#17324D] font-mono">3 Distributed</span>
        </Card>

        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <span className="text-xs font-semibold text-[#667085] block mb-1">Approvals</span>
          <span className={`text-sm font-bold font-mono ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
            {isQuorumAchieved ? '3 / 3 Complete' : '2 / 3 Pending'}
          </span>
        </Card>

        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <span className="text-xs font-semibold text-[#667085] block mb-1">Access</span>
          <span className={`text-sm font-bold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#667085]'}`}>
            {isQuorumAchieved ? 'Authorized' : 'Locked'}
          </span>
        </Card>

        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs col-span-2 sm:col-span-1">
          <span className="text-xs font-semibold text-[#667085] block mb-1">Exam Window</span>
          <span className="text-sm font-bold text-[#17324D] font-mono">09:55 – 12:00</span>
        </Card>
      </div>

      {/* TWO COLUMN CORE: FRAGMENTS, AUTHORIZATION & ACCESS CONDITIONS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* LEFT COLUMN: SECTION 3 (FRAGMENTS) & SECTION 4 (AUTHORIZATION) */}
        <div className="space-y-6">
          {/* SECTION 3 — FRAGMENT STATUS */}
          <Card
            className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs"
            header={
              <div className="flex items-center justify-between w-full">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-[#17324D]" />
                  <h3 className="text-sm font-bold text-[#17324D]">
                    Fragment Status
                  </h3>
                </div>
                <Badge variant="success" size="sm">
                  3 of 3 Secure
                </Badge>
              </div>
            }
          >
            <p className="text-xs text-[#667085] leading-relaxed">
              The question paper package is fragmented and stored across isolated secure storage nodes. No single location holds sufficient data to access the paper.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
              <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between">
                <div>
                  <span className="font-bold text-xs text-[#1F2933] block">Fragment A</span>
                  <span className="text-[10px] text-[#667085]">Storage Node 1</span>
                </div>
                <Badge variant="success" size="sm" dot>
                  Secure
                </Badge>
              </div>

              <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between">
                <div>
                  <span className="font-bold text-xs text-[#1F2933] block">Fragment B</span>
                  <span className="text-[10px] text-[#667085]">Storage Node 2</span>
                </div>
                <Badge variant="success" size="sm" dot>
                  Secure
                </Badge>
              </div>

              <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between">
                <div>
                  <span className="font-bold text-xs text-[#1F2933] block">Fragment C</span>
                  <span className="text-[10px] text-[#667085]">Storage Node 3</span>
                </div>
                <Badge variant="success" size="sm" dot>
                  Secure
                </Badge>
              </div>
            </div>
          </Card>

          {/* SECTION 4 — AUTHORIZATION */}
          <Card
            className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
            header={
              <div className="flex items-center justify-between w-full">
                <div className="flex items-center gap-2">
                  <UserCheck className="w-4 h-4 text-[#B7791F]" />
                  <h3 className="text-sm font-bold text-[#17324D]">
                    Authorization & Quorum
                  </h3>
                </div>
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-[#667085]">Quorum:</span>
                  <span className={`font-bold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
                    {paper.currentApprovals} / {paper.requiredApprovals} (Required: {paper.requiredApprovals})
                  </span>
                </div>
              </div>
            }
          >
            <div className="space-y-2.5">
              {/* Officer A */}
              <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between">
                <div>
                  <span className="font-bold text-xs text-[#1F2933] block">{officers.officerA.name}</span>
                  <span className="text-[11px] text-[#667085]">Role: {officers.officerA.role}</span>
                </div>
                <Badge variant="success" size="sm" dot>
                  Approved
                </Badge>
              </div>

              {/* Officer B */}
              <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between">
                <div>
                  <span className="font-bold text-xs text-[#1F2933] block">{officers.officerB.name}</span>
                  <span className="text-[11px] text-[#667085]">Role: {officers.officerB.role}</span>
                </div>
                <Badge variant="success" size="sm" dot>
                  Approved
                </Badge>
              </div>

              {/* Officer C */}
              <div className={`p-3 rounded-lg border flex items-center justify-between transition-colors ${
                isQuorumAchieved ? 'bg-[#F1F4F7] border-[#D5DDE5]' : 'bg-[#FFFAEB] border-[#FEDF89]'
              }`}>
                <div>
                  <span className="font-bold text-xs text-[#1F2933] block">{officers.officerC.name}</span>
                  <span className="text-[11px] text-[#667085]">Role: {officers.officerC.role}</span>
                </div>
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
            </div>

            {/* SECTION 7 — DEMO STATE CONTROLS */}
            <div className="pt-3 border-t border-[#D5DDE5] flex items-center justify-between gap-3">
              <span className="text-[11px] text-[#667085]">
                Interactive simulation:
              </span>
              <div className="flex items-center gap-2">
                {!isQuorumAchieved ? (
                  <Button
                    variant="primary"
                    size="sm"
                    icon={Play}
                    onClick={handleSimulateApproval}
                  >
                    Simulate Final Approval
                  </Button>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    icon={RotateCcw}
                    onClick={handleResetDemo}
                  >
                    Reset Demo State
                  </Button>
                )}
              </div>
            </div>
          </Card>
        </div>

        {/* RIGHT COLUMN: SECTION 5 (ACCESS CONDITIONS) & SECTION 6 (TIMELINE) */}
        <div className="space-y-6">
          {/* SECTION 5 — ACCESS CONDITIONS */}
          <Card
            className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs"
            header={
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#667085]" />
                <h3 className="text-sm font-bold text-[#17324D]">
                  Access Conditions
                </h3>
              </div>
            }
          >
            <div className="p-3.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] space-y-2.5 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Exam window:</span>
                <span className="font-mono font-bold text-[#17324D]">09:55 – 12:00</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Current access:</span>
                <span className={`font-semibold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#667085]'}`}>
                  {isQuorumAchieved ? 'Ready for Release' : 'Locked'}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Required quorum:</span>
                <span className="text-[#1F2933] font-medium">3 approvals</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Decryption:</span>
                <span className={`font-semibold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
                  {isQuorumAchieved ? 'Authorized for Exam Release' : 'Not authorized'}
                </span>
              </div>
            </div>

            <p className="text-[11px] text-[#667085] leading-snug">
              {isQuorumAchieved
                ? 'All access conditions are satisfied. Paper will be assembled during the designated examination window.'
                : 'Access will remain locked until all 3 authorized officers sign the authorization request.'}
            </p>
          </Card>

          {/* SECTION 6 — SECURITY TIMELINE */}
          <Card
            className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs"
            header={
              <div className="flex items-center justify-between w-full">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-[#667085]" />
                  <h3 className="text-sm font-bold text-[#17324D]">
                    Security Timeline
                  </h3>
                </div>
                <span className="text-[10px] text-[#667085] font-mono">
                  Chronological Record
                </span>
              </div>
            }
          >
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
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
      </div>
    </PageContainer>
  );
}
