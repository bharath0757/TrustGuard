import React from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  FileText, 
  CheckSquare, 
  AlertTriangle, 
  History, 
  CheckCircle2, 
  Clock, 
  Lock, 
  ArrowRight,
  ShieldCheck,
  Building2,
  FileCheck
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

export function DashboardPage() {
  const navigate = useNavigate();
  const { 
    paper, 
    activeThreatCount, 
    auditEvents, 
    isQuorumAchieved 
  } = useTrustGuard();

  const pendingApprovalsCount = isQuorumAchieved ? 0 : 1;
  const recentEvents = auditEvents.slice(0, 4);

  return (
    <PageContainer
      title="Examination Security Dashboard"
      subtitle="Monitor protected question papers, approval status, security alerts and recent activity."
    >
      {/* 1. TOP SUMMARY METRICS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Protected Papers */}
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs hover:border-[#AAB7C4] transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Protected papers</span>
            <FileText className="w-4 h-4 text-[#667085]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#17324D]">12</span>
            <span className="text-xs text-[#2E7D5B] font-semibold">All Encrypted</span>
          </div>
        </Card>

        {/* Pending Approvals */}
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs hover:border-[#AAB7C4] transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Pending approvals</span>
            <CheckSquare className="w-4 h-4 text-[#B7791F]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-bold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
              {pendingApprovalsCount}
            </span>
            <span className="text-xs text-[#667085] font-medium">
              {isQuorumAchieved ? 'All Signed' : 'Awaiting Signatures'}
            </span>
          </div>
        </Card>

        {/* Security Alerts */}
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs hover:border-[#AAB7C4] transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Security alerts</span>
            <AlertTriangle className="w-4 h-4 text-[#C44747]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#C44747]">
              {activeThreatCount}
            </span>
            <span className="text-xs text-[#667085] font-medium">Under Review</span>
          </div>
        </Card>

        {/* Recent Audit Events */}
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs hover:border-[#AAB7C4] transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Recent audit events</span>
            <History className="w-4 h-4 text-[#667085]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#17324D]">
              {auditEvents.length}
            </span>
            <span className="text-xs text-[#667085] font-medium">Logged Today</span>
          </div>
        </Card>
      </div>

      {/* 2. PROMINENT SECTION: Current Question Paper */}
      <Card
        className="p-5 bg-white border border-[#C7D0DA] shadow-xs"
        header={
          <div className="flex items-center justify-between w-full">
            <div>
              <h2 className="text-base font-bold text-[#17324D]">
                Current Question Paper
              </h2>
              <p className="text-xs text-[#667085] mt-0.5 font-normal">
                Active examination package undergoing authorization ceremony
              </p>
            </div>
            <Badge variant="info" size="sm" className="font-mono font-semibold">
              {paper.id}
            </Badge>
          </div>
        }
      >
        {/* Paper Details Header */}
        <div className="pb-4 mb-4 border-b border-[#D5DDE5] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-[#17324D]">
              {paper.name}
            </h3>
            <p className="text-xs text-[#667085] mt-0.5">
              Subject: Physics, Chemistry & Mathematics • Scheduled Window: {paper.examWindow}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/approvals')}
            >
              Review Approvals
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => navigate(`/papers/${paper.id}`)}
            >
              Paper Details
            </Button>
          </div>
        </div>

        {/* Five Security States Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
          {/* State 1: Encryption */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
            <span className="text-[11px] font-medium text-[#667085] block mb-1">Encryption</span>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
              <span className="text-xs font-semibold text-[#2E7D5B]">Complete</span>
            </div>
          </div>

          {/* State 2: Fragmentation */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
            <span className="text-[11px] font-medium text-[#667085] block mb-1">Fragmentation</span>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
              <span className="text-xs font-semibold text-[#2E7D5B]">Complete</span>
            </div>
          </div>

          {/* State 3: Distribution */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
            <span className="text-[11px] font-medium text-[#667085] block mb-1">Distribution</span>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
              <span className="text-xs font-semibold text-[#2E7D5B]">Complete</span>
            </div>
          </div>

          {/* State 4: Approvals */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
            <span className="text-[11px] font-medium text-[#667085] block mb-1">Approvals</span>
            <div className="flex items-center gap-1.5">
              {isQuorumAchieved ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
                  <span className="text-xs font-semibold text-[#2E7D5B]">3 / 3</span>
                </>
              ) : (
                <>
                  <Clock className="w-4 h-4 text-[#B7791F]" />
                  <span className="text-xs font-semibold text-[#B7791F]">2 / 3</span>
                </>
              )}
            </div>
          </div>

          {/* State 5: Access */}
          <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5]">
            <span className="text-[11px] font-medium text-[#667085] block mb-1">Access</span>
            <div className="flex items-center gap-1.5">
              {isQuorumAchieved ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
                  <span className="text-xs font-semibold text-[#2E7D5B]">Authorized</span>
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4 text-[#667085]" />
                  <span className="text-xs font-semibold text-[#667085]">Locked</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Simple Lifecycle Steps */}
        <div className="pt-4 border-t border-[#D5DDE5]">
          <span className="text-xs font-bold text-[#344054] uppercase tracking-wider block mb-3">
            Security Lifecycle Stage
          </span>

          <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
            {/* Step 1 */}
            <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-[#ECFDF3] text-[#2E7D5B] border border-[#D1FADF] text-xs font-bold flex items-center justify-center shrink-0">
                ✓
              </span>
              <span className="text-xs font-medium text-[#344054]">Paper Created</span>
            </div>

            {/* Step 2 */}
            <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-[#ECFDF3] text-[#2E7D5B] border border-[#D1FADF] text-xs font-bold flex items-center justify-center shrink-0">
                ✓
              </span>
              <span className="text-xs font-medium text-[#344054]">Protected</span>
            </div>

            {/* Step 3 */}
            <div className="p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-[#ECFDF3] text-[#2E7D5B] border border-[#D1FADF] text-xs font-bold flex items-center justify-center shrink-0">
                ✓
              </span>
              <span className="text-xs font-medium text-[#344054]">Distributed</span>
            </div>

            {/* Step 4: Awaiting Approval or Completed */}
            <div className={`p-2.5 rounded-lg border flex items-center gap-2 ${
              isQuorumAchieved 
                ? 'bg-[#F1F4F7] border-[#D5DDE5]' 
                : 'bg-[#FFFAEB] border-[#FEDF89]'
            }`}>
              <span className={`w-5 h-5 rounded-full text-xs font-bold flex items-center justify-center shrink-0 ${
                isQuorumAchieved
                  ? 'bg-[#ECFDF3] text-[#2E7D5B] border border-[#D1FADF]'
                  : 'bg-[#FEF0C7] text-[#B7791F] border border-[#FEDF89]'
              }`}>
                {isQuorumAchieved ? '✓' : '4'}
              </span>
              <span className={`text-xs font-semibold ${isQuorumAchieved ? 'text-[#344054]' : 'text-[#B7791F]'}`}>
                {isQuorumAchieved ? 'Approved (3/3)' : 'Awaiting Approval'}
              </span>
            </div>

            {/* Step 5: Access Authorized */}
            <div className={`p-2.5 rounded-lg border flex items-center gap-2 ${
              isQuorumAchieved 
                ? 'bg-[#ECFDF3] border-[#D1FADF]' 
                : 'bg-[#F1F4F7] border-[#D5DDE5] opacity-60'
            }`}>
              <span className={`w-5 h-5 rounded-full text-xs font-bold flex items-center justify-center shrink-0 ${
                isQuorumAchieved
                  ? 'bg-[#2E7D5B] text-white border border-[#2E7D5B]'
                  : 'bg-[#F2F4F7] text-[#667085] border border-[#D5DDE5]'
              }`}>
                {isQuorumAchieved ? '✓' : '5'}
              </span>
              <span className={`text-xs font-semibold ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#667085]'}`}>
                Access Authorized
              </span>
            </div>
          </div>
        </div>
      </Card>

      {/* 3. RECENT ACTIVITY SECTION */}
      <Card
        className="p-5 bg-white border border-[#C7D0DA] shadow-xs"
        header={
          <div className="flex items-center justify-between w-full">
            <h3 className="text-sm font-bold text-[#17324D]">
              Recent Activity
            </h3>
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-[#667085] hover:text-[#17324D] p-0"
              onClick={() => navigate('/audit')}
            >
              View full audit log →
            </Button>
          </div>
        }
      >
        <div className="space-y-2.5">
          {recentEvents.map((evt, idx) => (
            <div
              key={idx}
              className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs hover:border-[#AAB7C4] hover:bg-white transition-colors"
            >
              <div className="flex items-start sm:items-center gap-2.5">
                {evt.result === 'Blocked' ? (
                  <AlertTriangle className="w-4 h-4 text-[#C44747] shrink-0 mt-0.5 sm:mt-0" />
                ) : evt.type === 'Approval' ? (
                  <CheckSquare className="w-4 h-4 text-[#B7791F] shrink-0 mt-0.5 sm:mt-0" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-[#2E7D5B] shrink-0 mt-0.5 sm:mt-0" />
                )}
                <div>
                  <span className="font-semibold text-[#1F2933]">
                    {evt.action}
                  </span>
                  <p className="text-[11px] text-[#667085] mt-0.5">
                    Paper: <span className="text-[#17324D] font-mono font-semibold">{evt.paper}</span> • Actor: {evt.actor}
                  </p>
                </div>
              </div>
              <span className="text-[11px] text-[#667085] shrink-0 font-mono">
                {evt.time}
              </span>
            </div>
          ))}
        </div>
      </Card>
    </PageContainer>
  );
}
