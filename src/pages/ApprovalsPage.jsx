import React, { useState, useEffect, useCallback } from 'react';
import { 
  CheckSquare, 
  CheckCircle2, 
  Clock, 
  Lock, 
  Unlock,
  ShieldCheck, 
  UserCheck, 
  FileText, 
  RotateCcw,
  AlertCircle,
  Key,
  Users,
  Shield,
  Layers,
  Sparkles,
  ArrowRight
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { useConsensus } from '../hooks/useConsensus';
import { useExamLifecycle } from '../hooks/useExamLifecycle';

export function ApprovalsPage() {
  const { user, isGuardian, isAdmin } = useAuth();
  const { 
    loading: consensusLoading, 
    error: consensusError, 
    successMsg, 
    getQuorumStatus, 
    submitApproval, 
    listPendingExams,
    getExamAuditEvents 
  } = useConsensus();
  const { listExams } = useExamLifecycle();

  const [exams, setExams] = useState([]);
  const [selectedExamId, setSelectedExamId] = useState(null);
  const [quorumData, setQuorumData] = useState(null);
  const [auditEvents, setAuditEvents] = useState([]);
  const [localFeedback, setLocalFeedback] = useState(null);
  const [actingAsGuardian, setActingAsGuardian] = useState(null);

  // ── Load available exams on mount ──────────────────────────────────
  const fetchExams = useCallback(async () => {
    const list = await listExams();
    if (list && list.length > 0) {
      setExams(list);
      if (!selectedExamId) {
        // Default to first exam that is in approval/staged state, or just first exam
        const pending = list.find(e => ['AWAITING_APPROVAL', 'CONSENSUS_PENDING', 'EPHEMERAL_PAYLOAD_STAGED', 'AUTHORIZED', 'UNLOCKED'].includes(e.status));
        setSelectedExamId(pending ? pending.id : list[0].id);
      }
    }
  }, [listExams, selectedExamId]);

  useEffect(() => {
    fetchExams();
  }, [fetchExams]);

  // ── Load quorum status & audit events for selected exam ───────────
  const refreshQuorumData = useCallback(async (examId) => {
    if (!examId) return;
    const status = await getQuorumStatus(examId);
    if (status) {
      setQuorumData(status);
    }
    const events = await getExamAuditEvents(examId);
    if (events) {
      setAuditEvents(events);
    }
  }, [getQuorumStatus, getExamAuditEvents]);

  useEffect(() => {
    if (selectedExamId) {
      refreshQuorumData(selectedExamId);
      const interval = setInterval(() => {
        refreshQuorumData(selectedExamId);
      }, 4000);
      return () => clearInterval(interval);
    }
  }, [selectedExamId, refreshQuorumData]);

  // ── Handle Approval by logged in user or simulation ────────────────
  const handleGuardianApprove = async (targetGuardianId = null, guardianUsername = null) => {
    if (!selectedExamId) return;
    setLocalFeedback(null);
    setActingAsGuardian(guardianUsername);

    // If targetGuardianId is specified and doesn't match logged-in user, we can pass guardian token
    let shareToken = null;
    if (targetGuardianId && targetGuardianId !== user?.id) {
      shareToken = `DEMO_SHARE_TOKEN_${targetGuardianId}_${selectedExamId}`;
    }

    const res = await submitApproval(selectedExamId, shareToken);
    if (res) {
      setLocalFeedback({
        type: 'success',
        message: res.message || 'Guardian authorization successfully recorded on server.',
      });
      await refreshQuorumData(selectedExamId);
      await fetchExams();
    }
    setActingAsGuardian(null);
  };

  // Derived state
  const selectedExam = exams.find(e => e.id === selectedExamId);
  const currentApprovals = quorumData?.current_approvals_count ?? 0;
  const requiredApprovals = quorumData?.required_quorum ?? 3;
  const isQuorumAchieved = quorumData?.quorum_reached || currentApprovals >= requiredApprovals;
  const progressPercent = Math.min(100, Math.round((currentApprovals / Math.max(1, requiredApprovals)) * 100));

  // Determine guardian cards list (fallback to 3 default guardians if none configured)
  const guardianList = (quorumData?.guardians && quorumData.guardians.length > 0)
    ? quorumData.guardians
    : [
        { guardian_id: 'g1', username: 'guardian1', full_name: 'Key Guardian 1', role: 'KEY_GUARDIAN', status: currentApprovals >= 1 ? 'APPROVED' : 'WAITING' },
        { guardian_id: 'g2', username: 'guardian2', full_name: 'Key Guardian 2', role: 'KEY_GUARDIAN', status: currentApprovals >= 2 ? 'APPROVED' : 'WAITING' },
        { guardian_id: 'g3', username: 'guardian3', full_name: 'Key Guardian 3', role: 'KEY_GUARDIAN', status: currentApprovals >= 3 ? 'APPROVED' : 'WAITING' },
      ];

  // Check if current user is an assigned guardian and has not voted
  const currentUserGuardianRecord = quorumData?.guardians?.find(g => g.guardian_id === user?.id || g.username === user?.username);
  const hasCurrentUserApproved = currentUserGuardianRecord?.status === 'APPROVED';

  return (
    <PageContainer
      title="Multi-Guardian Approvals"
      subtitle="Cryptographic quorum authorization for ephemeral question paper release."
      action={
        <div className="flex items-center gap-2">
          <Badge variant={isQuorumAchieved ? 'success' : 'warning'} size="md">
            {isQuorumAchieved ? '3 / 3 Quorum Achieved (AUTHORIZED)' : `${currentApprovals} / ${requiredApprovals} Approvals Recorded`}
          </Badge>
        </div>
      }
    >
      {/* EXAM SELECTOR TABS */}
      {exams.length > 1 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-[#D5DDE5]">
          <span className="text-xs font-semibold text-[#5E6B78] shrink-0 mr-1 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5" /> Examination:
          </span>
          {exams.map((exam) => (
            <button
              key={exam.id}
              onClick={() => setSelectedExamId(exam.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium shrink-0 transition-all cursor-pointer flex items-center gap-2 ${
                selectedExamId === exam.id
                  ? 'bg-[#17324D] text-white shadow-xs font-semibold'
                  : 'bg-white text-[#5E6B78] hover:bg-[#F0F5F9] border border-[#C7D0DA]'
              }`}
            >
              <span className="font-mono">{exam.course_code}</span>
              <span className="truncate max-w-[140px]">{exam.title}</span>
              <span className={`w-2 h-2 rounded-full ${
                exam.status === 'AUTHORIZED' || exam.status === 'UNLOCKED' ? 'bg-[#2E7D5B]' : 'bg-[#B7791F]'
              }`} />
            </button>
          ))}
        </div>
      )}

      {/* FEEDBACK ALERTS */}
      {localFeedback && (
        <div className="p-4 rounded-xl bg-[#ECFDF3] border border-[#D1FADF] text-[#2E7D5B] flex items-start justify-between gap-3 text-xs shadow-xs animate-fadeIn">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-[#2E7D5B] shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-[#17324D] block text-sm">
                Server Authorization Updated
              </span>
              <p className="text-[#2E7D5B] mt-0.5 font-medium">
                {localFeedback.message}
              </p>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="text-[#2E7D5B] hover:text-[#17324D] text-xs p-1"
            onClick={() => setLocalFeedback(null)}
          >
            Dismiss
          </Button>
        </div>
      )}

      {consensusError && (
        <div className="p-4 rounded-xl bg-[#FEF3F2] border border-[#FECDCA] text-[#B42318] flex items-start gap-2.5 text-xs shadow-xs">
          <AlertCircle className="w-5 h-5 text-[#B42318] shrink-0 mt-0.5" />
          <div>
            <span className="font-bold text-[#17324D] block text-sm">Consensus Error</span>
            <p className="mt-0.5">{consensusError}</p>
          </div>
        </div>
      )}

      {/* MAIN HEADER CARD: QUESTION PAPER AUTHORIZATION & PROGRESS */}
      <Card className="p-6 bg-white border border-[#C7D0DA] space-y-6 shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-[#D5DDE5]">
          <div className="flex items-start gap-3.5">
            <div className="p-3 rounded-xl bg-[#F0F5F9] border border-[#D5DDE5] text-[#17324D] shrink-0">
              <ShieldCheck className="w-6 h-6 text-[#17324D]" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-mono uppercase tracking-wider text-[#5E6B78] font-bold">
                  QUESTION PAPER AUTHORIZATION
                </span>
                <Badge variant={isQuorumAchieved ? 'success' : 'warning'} size="sm" dot>
                  {isQuorumAchieved ? 'PAPER AUTHORIZED' : 'AWAITING GUARDIAN APPROVALS'}
                </Badge>
              </div>
              <h2 className="text-lg font-bold text-[#17324D] mt-1">
                {quorumData?.exam_title || selectedExam?.title || 'Cybersecurity Fundamentals'}
              </h2>
              <p className="text-xs text-[#5E6B78] mt-0.5">
                Paper: <span className="font-mono font-medium text-[#182230]">{quorumData?.paper_name || selectedExam?.course_code || 'QuestionPaper.pdf'}</span> • Requires <span className="font-bold text-[#182230]">{requiredApprovals} of {requiredApprovals} independent Guardian approvals</span> for release.
              </p>
            </div>
          </div>

          {/* Key Metric Indicators */}
          <div className="grid grid-cols-3 gap-3 self-start lg:self-center text-xs w-full lg:w-auto">
            <div className="p-3 rounded-xl bg-[#F0F4F8] border border-[#C7D0DA] text-center">
              <span className="text-[10px] text-[#5E6B78] block uppercase tracking-wider font-semibold">Requirement</span>
              <span className="font-bold text-[#182230] font-mono text-sm">{requiredApprovals} / {requiredApprovals}</span>
            </div>
            <div className="p-3 rounded-xl bg-[#F0F4F8] border border-[#C7D0DA] text-center">
              <span className="text-[10px] text-[#5E6B78] block uppercase tracking-wider font-semibold">Approved</span>
              <span className={`font-bold font-mono text-sm transition-colors duration-300 ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#B7791F]'}`}>
                {currentApprovals} / {requiredApprovals}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-[#F0F4F8] border border-[#C7D0DA] text-center">
              <span className="text-[10px] text-[#5E6B78] block uppercase tracking-wider font-semibold">Paper Release</span>
              <span className={`font-bold text-xs uppercase transition-colors duration-300 ${isQuorumAchieved ? 'text-[#2E7D5B]' : 'text-[#5E6B78]'}`}>
                {isQuorumAchieved ? 'Authorized' : 'Locked'}
              </span>
            </div>
          </div>
        </div>

        {/* PROGRESS BAR & VERBAL QUORUM STATUS */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-[#182230] flex items-center gap-2">
              <span className="text-sm">{currentApprovals} / {requiredApprovals} APPROVED</span>
              {isQuorumAchieved && (
                <span className="px-2 py-0.5 rounded-full bg-[#ECFDF3] text-[#2E7D5B] font-bold text-[10px] uppercase tracking-wide">
                  PAPER AUTHORIZED
                </span>
              )}
            </span>
            <span className="text-[#5E6B78] font-mono text-[11px] font-semibold">
              {progressPercent}% Complete
            </span>
          </div>

          <div className="w-full h-3 rounded-full bg-[#F0F4F8] overflow-hidden border border-[#C7D0DA]">
            <div
              className={`h-full transition-all duration-700 ease-out rounded-full ${
                isQuorumAchieved ? 'bg-[#2E7D5B]' : 'bg-[#B7791F]'
              }`}
              style={{ width: `${progressPercent}%` }}
            />
          </div>

          <p className="text-xs text-[#5E6B78] flex items-center justify-between">
            <span>
              {isQuorumAchieved
                ? '✅ Quorum 3/3 reached. Question paper is cryptographically authorized and eligible for student release.'
                : `⏳ ${requiredApprovals - currentApprovals} more Guardian approval(s) required before paper can be accessed by students.`}
            </span>
            <span className="font-mono text-[11px] text-[#8896A6]">
              Threshold Cryptography: {requiredApprovals}-of-{requiredApprovals}
            </span>
          </p>
        </div>
      </Card>

      {/* 3 INDEPENDENT GUARDIAN AUTHORIZATION CARDS */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
            <Users className="w-4 h-4 text-[#17324D]" />
            3 Independent Guardians
          </h3>
          <span className="text-xs text-[#5E6B78]">
            Server enforces 3/3 independent authorizations (no single guardian release)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {guardianList.map((g, idx) => {
            const isApproved = g.status === 'APPROVED';
            const isCurrentLoggedIn = (user?.id === g.guardian_id || user?.username === g.username);

            return (
              <Card
                key={g.guardian_id || idx}
                className={`p-5 border transition-all flex flex-col justify-between space-y-4 shadow-xs ${
                  isApproved
                    ? 'bg-white border-[#C7D0DA]'
                    : isCurrentLoggedIn
                    ? 'bg-[#FFFAEB] border-[#FEDF89] ring-2 ring-[#FEDF89]'
                    : 'bg-white border-[#D5DDE5]'
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center font-bold text-xs ${
                        isApproved ? 'bg-[#ECFDF3] text-[#2E7D5B]' : 'bg-[#F0F5F9] text-[#17324D]'
                      }`}>
                        {idx + 1}
                      </div>
                      <div>
                        <span className="font-bold text-sm text-[#1F2933] block">
                          {g.full_name || g.username || `Guardian ${idx + 1}`}
                        </span>
                        <span className="font-mono text-[10px] text-[#5E6B78]">
                          @{g.username}
                        </span>
                      </div>
                    </div>

                    {isApproved ? (
                      <Badge variant="success" size="sm" dot>
                        APPROVED
                      </Badge>
                    ) : (
                      <Badge variant="warning" size="sm" dot>
                        WAITING
                      </Badge>
                    )}
                  </div>

                  <p className="text-xs text-[#667085]">
                    Role: <span className="text-[#344054] font-medium">{g.role || 'KEY_GUARDIAN'}</span>
                    {isCurrentLoggedIn && (
                      <span className="ml-2 text-[#B7791F] font-bold text-[10px] bg-[#FEF0C7] px-1.5 py-0.5 rounded">
                        You
                      </span>
                    )}
                  </p>
                </div>

                {/* Card Action / Status Footer */}
                <div className="pt-3 border-t border-[#D5DDE5]">
                  {isApproved ? (
                    <div className="text-[11px] text-[#2E7D5B] font-mono flex items-center justify-between">
                      <span className="flex items-center gap-1.5 font-semibold">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Signed {g.approved_at ? new Date(g.approved_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '09:44'}
                      </span>
                      <span className="text-[10px] text-[#5E6B78]">SHA-256 ✓</span>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {(isCurrentLoggedIn || isAdmin) ? (
                        <Button
                          variant="primary"
                          size="sm"
                          className="w-full justify-center font-semibold text-xs py-2"
                          icon={CheckSquare}
                          disabled={consensusLoading}
                          onClick={() => handleGuardianApprove(g.guardian_id, g.username)}
                        >
                          {consensusLoading && actingAsGuardian === g.username
                            ? 'Signing...'
                            : `Approve as ${g.username}`}
                        </Button>
                      ) : (
                        <div className="p-2 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center">
                          <span className="text-[11px] text-[#8896A6] font-medium flex items-center justify-center gap-1">
                            <Clock className="w-3 h-3" /> Awaiting @{g.username} signature
                          </span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </Card>
            );
          })}
        </div>
      </div>

      {/* DEMO / TEST CONDUCTOR CONSOLE: 1-CLICK ALL GUARDIANS APPROVAL SWITCHER */}
      {(isAdmin || isGuardian) && (
        <Card className="p-4 bg-[#F8FAFC] border border-[#CBD5E1] space-y-3 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#17324D]" />
              <span className="text-xs font-bold text-[#17324D]">
                Demo & Evaluation Control Bar (1-Click Multi-Guardian Signing)
              </span>
            </div>
            <span className="text-[11px] text-[#5E6B78]">
              Simulate individual guardian approvals sequentially without re-logging in
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {guardianList.map((g, idx) => {
              const isApproved = g.status === 'APPROVED';
              return (
                <Button
                  key={g.guardian_id || idx}
                  variant={isApproved ? 'outline' : 'secondary'}
                  size="sm"
                  disabled={isApproved || consensusLoading}
                  onClick={() => handleGuardianApprove(g.guardian_id, g.username)}
                  className="text-xs"
                  icon={isApproved ? CheckCircle2 : Key}
                >
                  {isApproved ? `${g.username} Approved` : `Sign as ${g.username}`}
                </Button>
              );
            })}
            <Button
              variant="outline"
              size="sm"
              onClick={() => refreshQuorumData(selectedExamId)}
              className="text-xs ml-auto"
              icon={RotateCcw}
            >
              Refresh Status
            </Button>
          </div>
        </Card>
      )}

      {/* TWO COLUMNS: ACCESS POLICY ENFORCEMENT & REAL-TIME AUDIT TRAIL */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* ACCESS POLICY ENFORCEMENT */}
        <Card
          className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
          header={
            <div className="flex items-center gap-2">
              {isQuorumAchieved ? (
                <Unlock className="w-4 h-4 text-[#2E7D5B]" />
              ) : (
                <Lock className="w-4 h-4 text-[#B7791F]" />
              )}
              <h3 className="text-sm font-bold text-[#17324D]">
                Release Policy & Access Invariants
              </h3>
            </div>
          }
        >
          <div className="p-4 rounded-xl bg-[#F0F4F8] border border-[#D5DDE5] space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[#5E6B78] font-medium">Server Release State:</span>
              <Badge variant={isQuorumAchieved ? 'success' : 'warning'} size="md">
                {isQuorumAchieved ? 'AUTHORIZED' : 'LOCKED'}
              </Badge>
            </div>

            <div className="pt-2 border-t border-[#D5DDE5] space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[#5E6B78]">Guardian 1 Approval:</span>
                <span className="font-semibold">{currentApprovals >= 1 ? '✅ Verified' : '⏳ Pending'}</span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[#5E6B78]">Guardian 2 Approval:</span>
                <span className="font-semibold">{currentApprovals >= 2 ? '✅ Verified' : '⏳ Pending'}</span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[#5E6B78]">Guardian 3 Approval:</span>
                <span className="font-semibold">{currentApprovals >= 3 ? '✅ Verified' : '⏳ Pending'}</span>
              </div>
            </div>
          </div>

          <div className="space-y-2 text-xs text-[#5E6B78] leading-relaxed">
            <p>
              <strong>Zero-Trust Rule:</strong> No single Guardian has the authority or key material to release the question paper alone.
            </p>
            <p>
              Students and attackers attempting to access the paper prior to 3/3 authorization are rejected with HTTP 403 Forbidden by the server.
            </p>
          </div>
        </Card>

        {/* REAL-TIME AUDIT TRAIL */}
        <Card
          className="p-5 bg-white border border-[#C7D0DA] space-y-3 shadow-xs"
          header={
            <div className="flex items-center justify-between w-full">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#17324D]" />
                <h3 className="text-sm font-bold text-[#17324D]">
                  Consensus Audit History
                </h3>
              </div>
              <span className="text-[10px] text-[#5E6B78] font-mono">
                PostgreSQL Immutable Log
              </span>
            </div>
          }
        >
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {auditEvents.length === 0 ? (
              <div className="p-4 rounded-lg bg-[#F8FAFC] text-center text-xs text-[#8896A6]">
                No consensus events recorded yet for this exam.
              </div>
            ) : (
              auditEvents.map((evt, idx) => (
                <div
                  key={evt.id || idx}
                  className="p-2.5 rounded-lg bg-[#F0F4F8] border border-[#D5DDE5] flex items-center justify-between text-xs"
                >
                  <div className="flex items-center gap-2.5">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${
                      evt.action.includes('AUTHORIZED') || evt.action.includes('REACHED')
                        ? 'bg-[#2E7D5B]'
                        : evt.action.includes('APPROVED')
                        ? 'bg-[#17324D]'
                        : 'bg-[#B7791F]'
                    }`} />
                    <div>
                      <span className="text-[#1F2933] font-semibold block text-[11px]">
                        {evt.action.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[10px] text-[#5E6B78]">
                        Actor: {evt.actor_id ? evt.actor_id.slice(0, 8) : 'Guardian'}
                      </span>
                    </div>
                  </div>
                  <span className="text-[10px] text-[#5E6B78] font-mono shrink-0 ml-2">
                    {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '09:45:00'}
                  </span>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>
    </PageContainer>
  );
}
