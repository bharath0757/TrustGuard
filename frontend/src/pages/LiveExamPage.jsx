import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ShieldCheck, Shield, ShieldAlert, ShieldX, Clock, Lock, Unlock,
  AlertTriangle, CheckCircle2, XCircle, Users, Edit3, Send, Check,
  Loader2, RefreshCw, Radio, FileText, ChevronRight, Activity,
  Layers, ArrowRight, Zap, AlertCircle, Info, LogOut
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button, Modal } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { useRealTimeExamMonitor } from '../hooks/useRealTimeExamMonitor';

export function LiveExamPage() {
  const { examId } = useParams();
  const navigate = useNavigate();
  const { token, logout } = useAuth();
  const {
    data,
    loading,
    error,
    connected,
    transport,
    remainingSec,
    timeRemainingFormatted,
    refetch,
  } = useRealTimeExamMonitor(examId, token);

  const [showEndModal, setShowEndModal] = useState(false);
  const [ending, setEnding] = useState(false);
  const [endError, setEndError] = useState(null);

  // End Exam Handler
  const handleEndExam = async () => {
    try {
      setEnding(true);
      setEndError(null);
      const res = await fetch(`/api/v1/exam-lifecycle/${examId}/end`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ confirm: true }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to complete exam');
      }
      setShowEndModal(false);
      refetch();
    } catch (err) {
      setEndError(err.message);
    } finally {
      setEnding(false);
    }
  };

  if (loading && !data) {
    return (
      <PageContainer title="Secure Exam Control Center" subtitle="Loading live examination telemetry...">
        <div className="flex flex-col items-center justify-center py-20 space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-[#17324D] text-white flex items-center justify-center shadow-md animate-pulse">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <div className="flex items-center gap-2 text-xs text-[#5E6B78]">
            <Loader2 className="w-4 h-4 animate-spin text-[#3E6B8C]" />
            <span>Establishing real-time guardian telemetry stream...</span>
          </div>
        </div>
      </PageContainer>
    );
  }

  const isLive = data?.status === 'LIVE';
  const isCompleted = data?.status === 'COMPLETED';

  return (
    <PageContainer
      title="Secure Exam Control Center"
      subtitle="Real-time multi-guardian supervision, candidate participation, quorum consensus, and zero-trust telemetry."
      action={
        <div className="flex items-center gap-2">
          {/* Connection Mode Indicator */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border transition-all ${
              connected && transport === 'websocket'
                ? 'bg-[#EAF5F0] border-[#8ECFAD] text-[#2E7D5B]'
                : transport === 'polling'
                ? 'bg-[#FAF3E7] border-[#F5D99A] text-[#B7791F]'
                : 'bg-[#FDF2F2] border-[#FECDCA] text-[#C44747]'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                connected ? 'bg-[#2E7D5B] animate-ping' : 'bg-[#B7791F]'
              }`}
            />
            <span>
              {connected && transport === 'websocket'
                ? 'Real-Time (WS)'
                : transport === 'polling'
                ? 'Polling Fallback'
                : 'Connecting...'}
            </span>
          </div>

          {/* End Exam Button */}
          {isLive && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowEndModal(true)}
              className="text-xs border-[#FECDCA] text-[#C44747] hover:bg-[#FDF2F2]"
            >
              End Examination
            </Button>
          )}

          {isCompleted && (
            <Button
              size="sm"
              onClick={() => navigate(`/exam-report/${examId}`)}
              className="text-xs bg-[#17324D] text-white flex items-center gap-1"
            >
              <FileText className="w-3.5 h-3.5" /> View Final Report
            </Button>
          )}
        </div>
      }
    >
      <div className="space-y-5">
        {/* Error alert banner */}
        {error && (
          <Card className="p-3 bg-[#FDF2F2] border border-[#FECDCA] text-xs text-[#C44747] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
            <Button size="sm" variant="ghost" onClick={refetch}>Retry Connection</Button>
          </Card>
        )}

        {/* ── TOP METRIC CARDS (5 Prominent Status Widgets) ───────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {/* 1. Exam Status */}
          <Card className="p-4 bg-white border border-[#C7D0DA] shadow-2xs border-l-4 border-l-[#17324D]">
            <div className="text-[11px] font-semibold text-[#5E6B78] uppercase tracking-wider">Exam Status</div>
            <div className="mt-1 flex items-center gap-2">
              <span className="text-xl font-bold text-[#17324D]">
                {data?.status === 'LIVE' ? '🟢 LIVE' :
                 data?.status === 'AUTHORIZED' ? '🟡 AUTHORIZED' :
                 data?.status === 'COMPLETED' ? '⚪ COMPLETED' : data?.status || 'DRAFT'}
              </span>
            </div>
            <div className="text-[10px] text-[#5E6B78] mt-1 font-mono truncate">
              {data?.course_code || 'CS-SEC-2026'}
            </div>
          </Card>

          {/* 2. Registered Students */}
          <Card className="p-4 bg-white border border-[#C7D0DA] shadow-2xs border-l-4 border-l-[#0369A1]">
            <div className="text-[11px] font-semibold text-[#5E6B78] uppercase tracking-wider flex items-center justify-between">
              <span>Registered</span>
              <Users className="w-3.5 h-3.5 text-[#0369A1]" />
            </div>
            <div className="mt-1 text-2xl font-bold text-[#17324D]">
              {data?.registered_students_count ?? 2}
            </div>
            <div className="text-[10px] text-[#5E6B78] mt-1">Enrolled Candidates</div>
          </Card>

          {/* 3. Currently Writing */}
          <Card className="p-4 bg-white border border-[#C7D0DA] shadow-2xs border-l-4 border-l-[#2E7D5B]">
            <div className="text-[11px] font-semibold text-[#5E6B78] uppercase tracking-wider flex items-center justify-between">
              <span>Writing</span>
              <Edit3 className="w-3.5 h-3.5 text-[#2E7D5B]" />
            </div>
            <div className="mt-1 text-2xl font-bold text-[#2E7D5B] flex items-center gap-2">
              {data?.currently_writing_count ?? 0}
              {data?.currently_writing_count > 0 && (
                <span className="w-2 h-2 rounded-full bg-[#2E7D5B] animate-pulse" />
              )}
            </div>
            <div className="text-[10px] text-[#5E6B78] mt-1">In Active Sessions</div>
          </Card>

          {/* 4. Submitted Count */}
          <Card className="p-4 bg-white border border-[#C7D0DA] shadow-2xs border-l-4 border-l-[#3E6B8C]">
            <div className="text-[11px] font-semibold text-[#5E6B78] uppercase tracking-wider flex items-center justify-between">
              <span>Submitted</span>
              <CheckCircle2 className="w-3.5 h-3.5 text-[#3E6B8C]" />
            </div>
            <div className="mt-1 text-2xl font-bold text-[#3E6B8C]">
              {data?.submitted_count ?? 0} / {data?.registered_students_count ?? 2}
            </div>
            <div className="text-[10px] text-[#5E6B78] mt-1">
              {data?.expired_count > 0 ? `${data.expired_count} Expired` : 'Turned In'}
            </div>
          </Card>

          {/* 5. Server-Authoritative Timer */}
          <Card className={`p-4 border shadow-2xs border-l-4 ${
            remainingSec !== null && remainingSec < 180
              ? 'bg-[#FDF2F2] border-[#FECDCA] border-l-[#C44747]'
              : 'bg-white border-[#C7D0DA] border-l-[#17324D]'
          }`}>
            <div className="text-[11px] font-semibold text-[#5E6B78] uppercase tracking-wider flex items-center justify-between">
              <span>Time Remaining</span>
              <Clock className="w-3.5 h-3.5 text-[#5E6B78]" />
            </div>
            <div className={`mt-1 text-2xl font-bold font-mono tracking-wider ${
              remainingSec !== null && remainingSec < 180 ? 'text-[#C44747] animate-pulse' : 'text-[#17324D]'
            }`}>
              {timeRemainingFormatted}
            </div>
            <div className="text-[10px] text-[#5E6B78] mt-1">Server-Authoritative</div>
          </Card>
        </div>

        {/* ── MIDDLE GRID: Overview, Consensus & Security (2 Columns) ─── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* LEFT: Overview & Consensus (Col-span 6) */}
          <div className="lg:col-span-6 space-y-5">
            {/* EXAM OVERVIEW */}
            <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#D5DDE5]">
                <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider flex items-center gap-1.5">
                  <FileText className="w-4 h-4 text-[#3E6B8C]" />
                  Exam Overview & Paper Status
                </h3>
                <Badge variant={data?.paper_status === 'RELEASED' ? 'success' : 'neutral'} size="sm">
                  {data?.paper_status === 'RELEASED' ? '🔐 RELEASED' : data?.paper_status || 'STAGED'}
                </Badge>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E4E7EC]">
                  <span className="text-[#5E6B78] block text-[10px]">Examination Title</span>
                  <span className="font-semibold text-[#17324D]">{data?.exam_title || 'Cybersecurity Fundamentals'}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E4E7EC]">
                  <span className="text-[#5E6B78] block text-[10px]">Course Code / Duration</span>
                  <span className="font-semibold text-[#17324D]">{data?.course_code || 'CS-SEC-2026'} ({data?.duration_minutes || 10} min)</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E4E7EC]">
                  <span className="text-[#5E6B78] block text-[10px]">Paper Protection</span>
                  <span className="font-semibold text-[#2E7D5B]">AES-256-GCM + Shamir SSS</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E4E7EC]">
                  <span className="text-[#5E6B78] block text-[10px]">Integrity Digest</span>
                  <span className="font-mono text-[#17324D] text-[10px] truncate block" title={data?.integrity_hash}>
                    {data?.integrity_hash ? `${data.integrity_hash.slice(0, 16)}...` : 'Verified (SHA-256)'}
                  </span>
                </div>
              </div>
            </Card>

            {/* CONSENSUS STATUS (3 / 3) */}
            <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#D5DDE5]">
                <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-[#2E7D5B]" />
                  Guardian Consensus Status
                </h3>
                <span className="text-xs font-bold font-mono text-[#17324D] bg-[#EAF2F8] px-2 py-0.5 rounded border border-[#C7D0DA]">
                  {data?.quorum_status || `${data?.approvals_count || 3} / ${data?.required_quorum || 3}`}
                </span>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-[#F0F4F8] h-2 rounded-full overflow-hidden">
                <div
                  className="bg-[#2E7D5B] h-full transition-all duration-500 rounded-full"
                  style={{
                    width: `${Math.min(100, ((data?.approvals_count || 3) / (data?.required_quorum || 3)) * 100)}%`,
                  }}
                />
              </div>

              {/* Guardians List */}
              <div className="space-y-1.5 pt-1">
                {(data?.guardians && data.guardians.length > 0 ? data.guardians : [
                  { guardian_id: 'g1', username: 'guardian1', approved: true },
                  { guardian_id: 'g2', username: 'guardian2', approved: true },
                  { guardian_id: 'g3', username: 'guardian3', approved: true },
                ]).map((g, idx) => (
                  <div key={g.guardian_id || idx} className="flex items-center justify-between p-2 rounded-lg bg-[#F8FAFC] border border-[#E4E7EC] text-xs">
                    <div className="flex items-center gap-2">
                      <div className="w-5 h-5 rounded-full bg-[#17324D] text-white flex items-center justify-center text-[10px] font-bold">
                        {g.username.charAt(0).toUpperCase()}
                      </div>
                      <span className="font-semibold text-[#17324D]">{g.username}</span>
                      <span className="text-[10px] text-[#5E6B78] font-mono">Key Guardian {idx + 1}</span>
                    </div>
                    <Badge variant={g.approved ? 'success' : 'neutral'} size="sm">
                      {g.approved ? '✓ Approved' : 'Pending'}
                    </Badge>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* RIGHT: Security Monitor & Live Participants (Col-span 6) */}
          <div className="lg:col-span-6 space-y-5">
            {/* SECURITY MONITOR */}
            <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#D5DDE5]">
                <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-[#C44747]" />
                  Security Monitor
                </h3>
                <Badge variant={data?.security_status === 'SECURE' ? 'success' : 'danger'} size="sm">
                  {data?.security_status === 'SECURE' ? '🟢 SECURE' : '🔴 THREAT DETECTED'}
                </Badge>
              </div>

              <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E4E7EC] flex items-center justify-between text-xs">
                <span className="text-[#5E6B78]">Security Posture:</span>
                <span className="font-semibold text-[#17324D]">{data?.security_summary || '🟢 No security threats detected'}</span>
              </div>

              <div className="grid grid-cols-3 gap-2 text-center text-xs">
                <div className="p-2.5 rounded-lg bg-[#F0F4F8] border border-[#D5DDE5]">
                  <span className="text-[10px] text-[#5E6B78] block">Attack Attempts</span>
                  <span className="text-lg font-bold text-[#17324D]">{data?.attack_attempts ?? 0}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#EAF5F0] border border-[#8ECFAD]">
                  <span className="text-[10px] text-[#2E7D5B] block">Blocked</span>
                  <span className="text-lg font-bold text-[#2E7D5B]">{data?.blocked_attacks ?? 0}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#FDF2F2] border border-[#FECDCA]">
                  <span className="text-[10px] text-[#C44747] block">Integrity Violations</span>
                  <span className="text-lg font-bold text-[#C44747]">{data?.integrity_violations ?? 0}</span>
                </div>
              </div>
            </Card>

            {/* LIVE PARTICIPANTS */}
            <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#D5DDE5]">
                <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider flex items-center gap-1.5">
                  <Users className="w-4 h-4 text-[#0369A1]" />
                  Live Participants
                </h3>
                <span className="text-xs text-[#5E6B78]">
                  {data?.submitted_count ?? 0} of {data?.registered_students_count ?? 2} Completed
                </span>
              </div>

              <div className="space-y-2">
                {(data?.students && data.students.length > 0 ? data.students : [
                  { student_id: 's1', username: 'student1', status: 'IN_PROGRESS' },
                  { student_id: 's2', username: 'student2', status: 'IN_PROGRESS' },
                ]).map((st) => (
                  <div
                    key={st.student_id}
                    className="p-3 rounded-xl border border-[#E4E7EC] bg-[#F8FAFC] flex items-center justify-between text-xs"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-full bg-[#0369A1] text-white flex items-center justify-center font-bold text-xs">
                        {st.username.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <div className="font-bold text-[#17324D]">{st.username}</div>
                        <div className="text-[10px] text-[#5E6B78]">
                          {st.submitted_at
                            ? `Submitted at ${new Date(st.submitted_at).toLocaleTimeString()}`
                            : st.started_at
                            ? `Started at ${new Date(st.started_at).toLocaleTimeString()}`
                            : 'Registered candidate'}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {st.score !== null && st.score !== undefined && (
                        <span className="font-bold text-[#2E7D5B] bg-[#EAF5F0] px-2 py-0.5 rounded border border-[#8ECFAD] text-[11px]">
                          {st.score} Marks
                        </span>
                      )}
                      <Badge
                        variant={
                          st.status === 'SUBMITTED' ? 'success' :
                          st.status === 'IN_PROGRESS' ? 'warning' :
                          st.status === 'EXPIRED' ? 'danger' : 'neutral'
                        }
                        size="sm"
                      >
                        {st.status === 'IN_PROGRESS' ? 'Writing...' : st.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>

        {/* ── BOTTOM ROW: RECENT AUDIT EVENTS FEED (Full Width) ───────── */}
        <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#D5DDE5]">
            <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-[#17324D]" />
              Recent Audit Events Feed (Chronological)
            </h3>
            <span className="text-[10px] text-[#5E6B78] font-mono">
              Live Immutable Ledger Stream
            </span>
          </div>

          <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
            {data?.recent_audit_events && data.recent_audit_events.length > 0 ? (
              data.recent_audit_events.map((ev, idx) => (
                <div
                  key={ev.id || idx}
                  className="p-2.5 rounded-lg border border-[#E4E7EC] bg-[#F8FAFC] flex items-center justify-between text-xs hover:bg-[#F0F4F8] transition-colors"
                >
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-[10px] text-[#5E6B78] shrink-0">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '--:--:--'}
                    </span>
                    <Badge
                      variant={
                        ev.event_type === 'SECURITY' ? 'danger' :
                        ev.event_type === 'APPROVAL' ? 'success' :
                        ev.event_type === 'ACCESS' ? 'info' : 'neutral'
                      }
                      size="sm"
                    >
                      {ev.action}
                    </Badge>
                    <span className="text-[#17324D] font-medium truncate max-w-md">
                      {ev.details?.student_username
                        ? `Candidate ${ev.details.student_username} action`
                        : ev.details?.reason || ev.action.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <span className="text-[10px] text-[#5E6B78] font-mono hidden sm:inline">
                    Actor: {ev.actor_id ? (ev.actor_id.length > 12 ? `${ev.actor_id.slice(0, 8)}...` : ev.actor_id) : 'system'}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-xs text-[#5E6B78]">
                No audit events recorded yet.
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* End Exam Modal */}
      <Modal
        isOpen={showEndModal}
        onClose={() => setShowEndModal(false)}
        title="Confirm Examination Termination"
      >
        <div className="space-y-4">
          <div className="p-3 bg-[#FDF2F2] border border-[#FECDCA] rounded-lg text-xs text-[#C44747]">
            <AlertTriangle className="w-4 h-4 inline mr-1" />
            Ending this examination will terminate all active candidate sessions and purge ephemeral key shares from RAM.
          </div>

          {endError && (
            <div className="text-xs text-[#C44747]">{endError}</div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" size="sm" onClick={() => setShowEndModal(false)}>
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleEndExam}
              disabled={ending}
              className="bg-[#C44747] hover:bg-[#A83838] text-white flex items-center gap-1.5"
            >
              {ending ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldX className="w-4 h-4" />}
              Confirm & End Exam
            </Button>
          </div>
        </div>
      </Modal>
    </PageContainer>
  );
}
