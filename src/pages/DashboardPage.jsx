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
  ShieldAlert,
  ArrowRight,
  ShieldCheck,
  Activity,
  Layers,
  FileCheck
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

// Realistic mock events for Dashboard Recent Threat Alerts panel
const DASHBOARD_MOCK_ALERTS = [
  {
    id: 'ALT-101',
    severity: 'Critical',
    title: 'Unauthorized paper access attempt blocked',
    paper: 'JEE-MOCK-001',
    time: '2 min ago',
    result: 'Access blocked',
  },
  {
    id: 'ALT-102',
    severity: 'Warning',
    title: 'Invalid quorum request',
    paper: 'NEET-MOCK-002',
    time: '8 min ago',
    result: 'Blocked',
  },
  {
    id: 'ALT-103',
    severity: 'Info',
    title: 'Simulated attack detected',
    paper: 'DEMO-003',
    time: '12 min ago',
    result: 'Recorded',
  },
];

export function DashboardPage() {
  const navigate = useNavigate();
  const { 
    paper, 
    auditEvents, 
    activeThreatCount, 
    isQuorumAchieved 
  } = useTrustGuard();

  const pendingApprovalsCount = isQuorumAchieved ? 0 : 1;
  const recentEvents = auditEvents.slice(0, 4);

  // Security Overview Paper Distribution metrics
  const pendingCount = isQuorumAchieved ? 0 : 1;
  const authorizedCount = isQuorumAchieved ? 2 : 1;
  const activeCount = paper.examAccess === 'Active' ? 1 : 0;

  return (
    <PageContainer
      title="Examination Security Dashboard"
      subtitle="Monitor protected question papers, authorization status, security alerts and recent activity."
      action={
        <span className="text-[11px] text-[#5E6B78] font-mono font-medium bg-[#F0F4F8] border border-[#C7D0DA] px-2.5 py-1 rounded-md">
          Last updated a few seconds ago
        </span>
      }
    >
      {/* 1. MAIN SUMMARY ROW — 4 Compact Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Protected Papers */}
        <Card className="p-4 bg-white border border-[#C7D0DA] border-l-4 border-l-[#2E7D5B] shadow-xs hover:-translate-y-0.5 hover:shadow-sm transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#5E6B78]">Protected papers</span>
            <div className="w-7 h-7 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] flex items-center justify-center text-[#2E7D5B]">
              <FileText className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#17324D] tracking-tight">12</span>
            <span className="text-xs text-[#2E7D5B] font-semibold bg-[#EAF5F0] px-2 py-0.5 rounded border border-[#B2D8C7]">
              All Encrypted
            </span>
          </div>
        </Card>

        {/* Pending Approvals */}
        <Card className="p-4 bg-white border border-[#C7D0DA] border-l-4 border-l-[#B7791F] shadow-xs hover:-translate-y-0.5 hover:shadow-sm transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#5E6B78]">Pending approvals</span>
            <div className="w-7 h-7 rounded-lg bg-[#FAF3E7] border border-[#E8D4B5] flex items-center justify-center text-[#B7791F]">
              <CheckSquare className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className={`text-2xl font-bold tracking-tight ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
              {pendingApprovalsCount}
            </span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${
              isQuorumAchieved 
                ? 'text-[#2E7D5B] bg-[#EAF5F0] border-[#B2D8C7]' 
                : 'text-[#B7791F] bg-[#FAF3E7] border-[#E8D4B5]'
            }`}>
              {isQuorumAchieved ? 'All Signed' : 'Awaiting Signatures'}
            </span>
          </div>
        </Card>

        {/* Active Security Alerts */}
        <Card className="p-4 bg-white border border-[#C7D0DA] border-l-4 border-l-[#C44747] shadow-xs hover:-translate-y-0.5 hover:shadow-sm transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#5E6B78]">Active security alerts</span>
            <div className="w-7 h-7 rounded-lg bg-[#FDF2F2] border border-[#F2C2C2] flex items-center justify-center text-[#C44747]">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#C44747] tracking-tight">
              {activeThreatCount}
            </span>
            <span className="text-xs text-[#C44747] font-semibold bg-[#FDF2F2] px-2 py-0.5 rounded border border-[#F2C2C2]">
              {activeThreatCount > 0 ? 'Action Required' : 'All Clear'}
            </span>
          </div>
        </Card>

        {/* Recent Audit Events */}
        <Card className="p-4 bg-white border border-[#C7D0DA] border-l-4 border-l-[#3E6B8C] shadow-xs hover:-translate-y-0.5 hover:shadow-sm transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#5E6B78]">Recent audit events</span>
            <div className="w-7 h-7 rounded-lg bg-[#EEF4F9] border border-[#C7D0DA] flex items-center justify-center text-[#3E6B8C]">
              <History className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#17324D] tracking-tight">
              {auditEvents.length}
            </span>
            <span className="text-xs text-[#3E6B8C] font-semibold bg-[#EEF4F9] px-2 py-0.5 rounded border border-[#C7D0DA]">
              Logged Today
            </span>
          </div>
        </Card>
      </div>

      {/* 2. MAIN CONTENT ROW 1 (Two-Column Layout) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* LEFT PANEL (Col-span 7): Compact Current Question Paper & Lifecycle */}
        <div className="lg:col-span-7">
          <Card className="p-4 sm:p-5 bg-white border border-[#C7D0DA] shadow-xs hover:-translate-y-0.5 transition-all duration-200">
            {/* Header Banner: Current Question Paper */}
            <div className="flex items-start justify-between gap-3 pb-3 border-b border-[#D5DDE5]">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#EEF4F9] border border-[#C7D0DA] text-[#17324D] shrink-0">
                  <FileText className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-bold text-[#17324D]">
                      Current question paper awaiting authorization
                    </h2>
                    <Badge variant="info" size="sm" className="font-mono font-semibold">
                      {paper.id}
                    </Badge>
                  </div>
                  <p className="text-xs text-[#5E6B78] mt-0.5 font-normal">
                    {paper.name} • Window: {paper.examWindow}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => navigate('/approvals')}
                >
                  Approvals
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => navigate(`/papers/${paper.id}`)}
                >
                  Details
                </Button>
              </div>
            </div>

            {/* Continuous Stage Pipeline: Paper Security Lifecycle */}
            <div className="pt-4 space-y-2.5">
              <span className="text-xs font-bold text-[#182230] uppercase tracking-wider block">
                Paper security lifecycle
              </span>

              {/* Continuous Stage Pipeline with single connector line */}
              <div className="relative pt-1">
                {/* Thin Connector Line */}
                <div className="hidden sm:block absolute top-4 left-5 right-5 h-0.5 bg-[#C7D0DA] z-0" aria-hidden="true" />

                <div className="grid grid-cols-2 sm:grid-cols-6 gap-2">
                  {/* Step 1: Created */}
                  <div className="relative z-10 p-2 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] flex items-center justify-center gap-1.5 text-center">
                    <span className="w-5 h-5 rounded-full bg-[#2E7D5B] text-white text-[11px] font-bold flex items-center justify-center shrink-0">
                      ✓
                    </span>
                    <span className="text-xs font-semibold text-[#182230]">Created</span>
                  </div>

                  {/* Step 2: Protected */}
                  <div className="relative z-10 p-2 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] flex items-center justify-center gap-1.5 text-center">
                    <span className="w-5 h-5 rounded-full bg-[#2E7D5B] text-white text-[11px] font-bold flex items-center justify-center shrink-0">
                      ✓
                    </span>
                    <span className="text-xs font-semibold text-[#182230]">Protected</span>
                  </div>

                  {/* Step 3: Distributed */}
                  <div className="relative z-10 p-2 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] flex items-center justify-center gap-1.5 text-center">
                    <span className="w-5 h-5 rounded-full bg-[#2E7D5B] text-white text-[11px] font-bold flex items-center justify-center shrink-0">
                      ✓
                    </span>
                    <span className="text-xs font-semibold text-[#182230]">Distributed</span>
                  </div>

                  {/* Step 4: Approval */}
                  <div className={`relative z-10 p-2 rounded-lg border flex items-center justify-center gap-1.5 text-center transition-all ${
                    isQuorumAchieved ? 'bg-[#EAF5F0] border-[#B2D8C7]' : 'bg-[#FAF3E7] border-[#E8D4B5]'
                  }`}>
                    <span className={`w-5 h-5 rounded-full text-[11px] font-bold flex items-center justify-center shrink-0 ${
                      isQuorumAchieved ? 'bg-[#2E7D5B] text-white' : 'bg-[#B7791F] text-white'
                    }`}>
                      {isQuorumAchieved ? '✓' : '4'}
                    </span>
                    <span className={`text-xs font-semibold ${isQuorumAchieved ? 'text-[#182230]' : 'text-[#B7791F]'}`}>
                      {isQuorumAchieved ? 'Approval' : 'Approval (2/3)'}
                    </span>
                  </div>

                  {/* Step 5: Authorized */}
                  <div className={`relative z-10 p-2 rounded-lg border flex items-center justify-center gap-1.5 text-center transition-all ${
                    isQuorumAchieved ? 'bg-[#EEF4F9] border-[#C7D0DA]' : 'bg-[#F0F4F8] border-[#C7D0DA] opacity-70'
                  }`}>
                    <span className={`w-5 h-5 rounded-full text-[11px] font-bold flex items-center justify-center shrink-0 ${
                      isQuorumAchieved ? 'bg-[#17324D] text-white' : 'bg-[#C7D0DA] text-[#5E6B78]'
                    }`}>
                      {isQuorumAchieved ? '✓' : '5'}
                    </span>
                    <span className={`text-xs font-semibold ${isQuorumAchieved ? 'text-[#17324D]' : 'text-[#5E6B78]'}`}>
                      Authorized
                    </span>
                  </div>

                  {/* Step 6: Active */}
                  <div className={`relative z-10 p-2 rounded-lg border flex items-center justify-center gap-1.5 text-center transition-all ${
                    paper.examAccess === 'Active' ? 'bg-[#EAF5F0] border-[#B2D8C7]' : 'bg-[#F0F4F8] border-[#C7D0DA] opacity-70'
                  }`}>
                    <span className={`w-5 h-5 rounded-full text-[11px] font-bold flex items-center justify-center shrink-0 ${
                      paper.examAccess === 'Active' ? 'bg-[#2E7D5B] text-white' : 'bg-[#C7D0DA] text-[#5E6B78]'
                    }`}>
                      {paper.examAccess === 'Active' ? '●' : '6'}
                    </span>
                    <span className={`text-xs font-semibold ${paper.examAccess === 'Active' ? 'text-[#2E7D5B]' : 'text-[#5E6B78]'}`}>
                      Active
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </div>

        {/* RIGHT PANEL (Col-span 5): Recent Threat Alerts (Compact, no empty vertical height) */}
        <div className="lg:col-span-5">
          <Card className="p-4 sm:p-5 bg-white border border-[#C7D0DA] shadow-xs hover:-translate-y-0.5 transition-all duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-[#D5DDE5] mb-3">
              <h3 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#C44747]" />
                Recent Threat Alerts
              </h3>
              <Button
                variant="ghost"
                size="sm"
                className="text-xs text-[#5E6B78] hover:text-[#17324D] p-0"
                onClick={() => navigate('/threat-alerts')}
              >
                View all →
              </Button>
            </div>

            <div className="space-y-2">
              {DASHBOARD_MOCK_ALERTS.map((alert) => {
                const isCritical = alert.severity === 'Critical';
                const isWarning = alert.severity === 'Warning';

                return (
                  <div
                    key={alert.id}
                    onClick={() => navigate('/threat-alerts')}
                    className={`p-2.5 rounded-lg border flex items-center justify-between gap-3 transition-all cursor-pointer hover:-translate-y-0.5 ${
                      isCritical
                        ? 'bg-[#FDF2F2] border-[#F2C2C2]'
                        : isWarning
                        ? 'bg-[#FAF3E7] border-[#E8D4B5]'
                        : 'bg-[#EEF4F9] border-[#C7D0DA]'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div className={`p-1 rounded shrink-0 ${
                        isCritical ? 'bg-[#C44747] text-white' : isWarning ? 'bg-[#B7791F] text-white' : 'bg-[#3E6B8C] text-white'
                      }`}>
                        {isCritical ? (
                          <ShieldAlert className="w-3.5 h-3.5" />
                        ) : isWarning ? (
                          <AlertTriangle className="w-3.5 h-3.5" />
                        ) : (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        )}
                      </div>

                      <div className="min-w-0">
                        <span className="font-bold text-[#182230] text-xs truncate block">
                          {alert.title}
                        </span>
                        <div className="flex items-center gap-1.5 text-[11px] text-[#5E6B78] font-mono mt-0.5">
                          <span className="font-semibold text-[#17324D]">{alert.paper}</span>
                          <span>•</span>
                          <span>{alert.time}</span>
                        </div>
                      </div>
                    </div>

                    <Badge
                      variant={isCritical ? 'danger' : isWarning ? 'warning' : 'info'}
                      size="sm"
                      className="shrink-0 text-[10px] px-1.5 py-0"
                    >
                      {alert.severity}
                    </Badge>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      </div>

      {/* 3. MAIN CONTENT ROW 2 (Two-Column Layout) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* LEFT PANEL (Col-span 7): Recent Audit Events */}
        <div className="lg:col-span-7">
          <Card className="p-4 sm:p-5 bg-white border border-[#C7D0DA] shadow-xs hover:-translate-y-0.5 transition-all duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-[#D5DDE5] mb-3">
              <h3 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
                <History className="w-4 h-4 text-[#3E6B8C]" />
                Recent Audit Events
              </h3>
              <Button
                variant="ghost"
                size="sm"
                className="text-xs text-[#5E6B78] hover:text-[#17324D] p-0"
                onClick={() => navigate('/audit')}
              >
                View full log →
              </Button>
            </div>

            <div className="space-y-2.5">
              {recentEvents.map((evt, idx) => (
                <div
                  key={idx}
                  onClick={() => navigate('/audit')}
                  className="p-2.5 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] flex items-center justify-between gap-3 text-xs hover:border-[#AAB7C4] hover:bg-white transition-all cursor-pointer"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className={`p-1.5 rounded-md shrink-0 ${
                      evt.result === 'Blocked' 
                        ? 'bg-[#FDF2F2] text-[#C44747] border border-[#F2C2C2]' 
                        : evt.type === 'Approval' 
                        ? 'bg-[#FAF3E7] text-[#B7791F] border border-[#E8D4B5]' 
                        : 'bg-[#EAF5F0] text-[#2E7D5B] border border-[#B2D8C7]'
                    }`}>
                      {evt.result === 'Blocked' ? (
                        <AlertTriangle className="w-3.5 h-3.5" />
                      ) : evt.type === 'Approval' ? (
                        <CheckSquare className="w-3.5 h-3.5" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5" />
                      )}
                    </div>
                    <div className="min-w-0">
                      <span className="font-semibold text-[#182230] truncate block">
                        {evt.action}
                      </span>
                      <p className="text-[11px] text-[#5E6B78] truncate mt-0.5">
                        Paper: <span className="text-[#17324D] font-mono font-semibold">{evt.paper}</span> • Actor: {evt.actor}
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-col items-end gap-1 shrink-0 font-mono">
                    <Badge variant={evt.type === 'Approval' ? 'warning' : evt.type === 'Security' ? 'danger' : 'info'} size="sm" className="text-[10px] px-1.5 py-0">
                      {evt.type}
                    </Badge>
                    <span className="text-[11px] text-[#5E6B78]">
                      {evt.time}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* RIGHT PANEL (Col-span 5): Security Overview Distribution */}
        <div className="lg:col-span-5">
          <Card className="p-4 sm:p-5 bg-white border border-[#C7D0DA] shadow-xs hover:-translate-y-0.5 transition-all duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-[#D5DDE5] mb-3">
              <h3 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#17324D]" />
                Security Overview
              </h3>
              <span className="text-xs text-[#5E6B78] font-mono font-semibold">
                14 Total Papers
              </span>
            </div>

            <div className="space-y-3.5">
              <p className="text-xs text-[#5E6B78]">
                Real-time status breakdown across registered examination packages.
              </p>

              {/* Segmented Distribution Bar */}
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs font-semibold">
                  <span className="text-[#182230]">Protection Distribution</span>
                  <span className="text-[#2E7D5B] font-mono">100% Encrypted</span>
                </div>
                <div className="w-full h-2.5 rounded-full bg-[#F0F4F8] border border-[#C7D0DA] overflow-hidden flex">
                  <div className="bg-[#2E7D5B] h-full" style={{ width: '85%' }} title="Protected (12)" />
                  <div className="bg-[#B7791F] h-full" style={{ width: '7%' }} title="Pending Approval (1)" />
                  <div className="bg-[#3E6B8C] h-full" style={{ width: '8%' }} title="Authorized (1)" />
                </div>
              </div>

              {/* Status Category Grid */}
              <div className="grid grid-cols-2 gap-2 pt-1">
                {/* Category 1: Protected */}
                <div className="p-2.5 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#2E7D5B]" />
                    <span className="text-xs font-semibold text-[#182230]">Protected</span>
                  </div>
                  <span className="text-xs font-bold text-[#2E7D5B] font-mono">12</span>
                </div>

                {/* Category 2: Pending Approval */}
                <div className="p-2.5 rounded-lg bg-[#FAF3E7] border border-[#E8D4B5] flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#B7791F]" />
                    <span className="text-xs font-semibold text-[#182230]">Pending</span>
                  </div>
                  <span className="text-xs font-bold text-[#B7791F] font-mono">{pendingCount}</span>
                </div>

                {/* Category 3: Authorized */}
                <div className="p-3 rounded-lg bg-[#EEF4F9] border border-[#C7D0DA] flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#3E6B8C]" />
                    <span className="text-xs font-semibold text-[#182230]">Authorized</span>
                  </div>
                  <span className="text-xs font-bold text-[#3E6B8C] font-mono">{authorizedCount}</span>
                </div>

                {/* Category 4: Active */}
                <div className="p-2.5 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#5E6B78]" />
                    <span className="text-xs font-semibold text-[#182230]">Active</span>
                  </div>
                  <span className="text-xs font-bold text-[#5E6B78] font-mono">{activeCount}</span>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </PageContainer>
  );
}


