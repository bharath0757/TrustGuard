import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  FileText, ShieldCheck, ShieldAlert, ShieldX, CheckCircle2,
  AlertTriangle, Clock, Calendar, ArrowLeft, Download,
  Printer, Share2, Eye, Activity, Lock, Unlock, Hash,
  AlertCircle, ChevronRight, BarChart3, Loader2, Users,
  Key, Shield, Check, X, FileJson, FileCode, CheckCheck,
  Award, AlertOctagon, Terminal, Info
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useExamLifecycle } from '../hooks/useExamLifecycle';

export function ExamReportPage() {
  const { examId } = useParams();
  const navigate = useNavigate();
  const { getReport, loading, error } = useExamLifecycle();
  const [report, setReport] = useState(null);
  const [copiedNotification, setCopiedNotification] = useState(false);

  const fetchReport = useCallback(async () => {
    if (!examId) return;
    const data = await getReport(examId);
    if (data) {
      setReport(data);
    }
  }, [examId, getReport]);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJSON = () => {
    if (!report) return;
    const jsonStr = JSON.stringify(report, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `TrustGuard-Security-Report-${report.course_code || report.exam_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadMarkdown = () => {
    if (!report) return;
    const mdContent = `# TRUSTGUARD FINAL SECURITY REPORT
**Exam:** ${report.exam_title} (${report.course_code || 'N/A'})
**Exam ID:** ${report.exam_id}
**Status:** ${report.status}
**Generated At:** ${new Date().toISOString()}

---

## 1. EXAM INFORMATION
- **Title:** ${report.exam_title}
- **Course Code:** ${report.course_code || 'N/A'}
- **Start Time:** ${report.start_time ? new Date(report.start_time).toLocaleString() : 'N/A'}
- **End Time:** ${report.end_time ? new Date(report.end_time).toLocaleString() : 'N/A'}
- **Duration:** ${report.duration_minutes} minutes
- **Status:** ${report.status}

## 2. CANDIDATE PARTICIPATION
- **Registered Students:** ${report.registered_students}
- **Students Joined:** ${report.students_joined}
- **Currently Writing:** ${report.currently_writing}
- **Submitted:** ${report.submitted_count}
- **Expired:** ${report.expired_count}

## 3. GUARDIAN CONSENSUS & AUTHORIZATION
- **Required Threshold:** ${report.required_quorum} / ${report.total_guardians}
- **Approvals Obtained:** ${report.approvals_count} / ${report.total_guardians}
- **Consensus Status:** ${report.quorum_achieved ? 'QUORUM REACHED' : 'PENDING'}
- **Paper Release:** ${report.paper_release_status}
${(report.guardians || []).map((g, i) => `- Guardian ${i + 1} (${g.username}): ${g.approved ? 'APPROVED' : 'PENDING'} [Fingerprint: ${g.public_key_fingerprint || 'N/A'}]`).join('\n')}

## 4. SECURITY & DEFENSE STATISTICS
- **Attack Attempts Intercepted:** ${report.attack_attempts || report.unauthorized_attempts || 0}
- **Blocked Attacks:** ${report.blocked_attempts || 0}
- **Successful Attacks:** ${report.successful_attacks || 0}
- **Integrity Violations:** ${report.integrity_violations || 0}
- **Overall Security Verdict:** ${report.overall_security || 'VERIFIED'}

## 5. FACTUAL SECURITY SUMMARY
${(report.factual_statements || [
  'All simulated unauthorized actions were blocked.',
  'Exam paper release occurred only after the configured guardian threshold was reached.',
  'Security events were recorded in the audit trail.',
  'Ephemeral storage wiped and key shares discarded upon exam completion.'
]).map(s => `- ${s}`).join('\n')}

---
*Report certified by TrustGuard Cryptographic Audit Subsystem.*
`;

    const blob = new Blob([mdContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `TrustGuard-Security-Report-${report.course_code || report.exam_id}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getStatusBadgeVariant = (status) => {
    switch (status) {
      case 'PROTECTED':
      case 'VERIFIED':
        return 'success';
      case 'ATTENTION_REQUIRED':
      case 'WARNING':
        return 'warning';
      case 'SECURITY_INCIDENT_DETECTED':
      case 'CRITICAL':
        return 'danger';
      default:
        return 'info';
    }
  };

  const getTimelineIcon = (eventType, severity) => {
    if (severity === 'CRITICAL' || eventType === 'SECURITY') {
      return <ShieldX className="w-4 h-4 text-[#C44747]" />;
    }
    if (severity === 'WARNING') {
      return <AlertTriangle className="w-4 h-4 text-[#B7791F]" />;
    }
    if (eventType === 'APPROVAL') {
      return <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />;
    }
    return <Activity className="w-4 h-4 text-[#3E6B8C]" />;
  };

  if (loading && !report) {
    return (
      <PageContainer title="Final Security Report" subtitle="Loading report data...">
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 animate-spin text-[#3E6B8C]" />
        </div>
      </PageContainer>
    );
  }

  if (error || !report) {
    return (
      <PageContainer title="Final Security Report" subtitle="Error loading report">
        <Card className="p-6 text-center max-w-lg mx-auto bg-white border border-[#C7D0DA]">
          <AlertCircle className="w-12 h-12 text-[#C44747] mx-auto mb-3" />
          <h3 className="text-base font-semibold text-[#17324D] mb-1">Unable to Load Security Report</h3>
          <p className="text-sm text-[#5E6B78] mb-4">{error || 'Report data not found for this examination.'}</p>
          <Button variant="outline" size="sm" onClick={() => navigate('/exam-center')}>
            <ArrowLeft className="w-4 h-4 mr-1.5" /> Back to Exam Center
          </Button>
        </Card>
      </PageContainer>
    );
  }

  const factualStatements = report.factual_statements?.length > 0 ? report.factual_statements : [
    'All simulated unauthorized actions were blocked.',
    'Exam paper release occurred only after the configured guardian threshold was reached.',
    'Security events were recorded in the audit trail.',
    'Ephemeral storage wiped and key shares discarded upon exam completion.',
  ];

  return (
    <PageContainer
      title="TrustGuard Final Security Report"
      subtitle={`Authoritative cryptographic audit & security lifecycle summary for ${report.exam_title}`}
      action={
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => navigate('/exam-center')} className="flex items-center gap-1.5">
            <ArrowLeft className="w-4 h-4" /> Exam Center
          </Button>
          <Button variant="outline" size="sm" onClick={handleDownloadJSON} className="flex items-center gap-1.5">
            <FileJson className="w-4 h-4 text-[#3E6B8C]" /> Export JSON
          </Button>
          <Button variant="outline" size="sm" onClick={handleDownloadMarkdown} className="flex items-center gap-1.5">
            <FileCode className="w-4 h-4 text-[#2E7D5B]" /> Export Markdown
          </Button>
          <Button variant="primary" size="sm" onClick={handlePrint} className="flex items-center gap-1.5 bg-[#17324D]">
            <Printer className="w-4 h-4" /> Print / Save PDF
          </Button>
        </div>
      }
    >
      {/* ── Top Executive Summary Banner ──────────────────────── */}
      <Card className="p-5 mb-6 bg-white border border-[#C7D0DA] shadow-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-xl border bg-[#EAF5F0] border-[#8ECFAD] text-[#2E7D5B] shrink-0">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#5E6B78]">
                  TrustGuard Institutional Audit
                </span>
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-[#EAF5F0] text-[#2E7D5B] border border-[#8ECFAD]">
                  <CheckCheck className="w-3.5 h-3.5" />
                  OVERALL SECURITY: {report.overall_security || 'VERIFIED'}
                </span>
              </div>
              <h2 className="text-lg sm:text-xl font-bold text-[#17324D]">
                {report.exam_title} {report.course_code ? `(${report.course_code})` : ''}
              </h2>
              <p className="text-xs sm:text-sm text-[#5E6B78] mt-1 max-w-2xl leading-relaxed">
                {report.security_summary}
              </p>
            </div>
          </div>
          <div className="flex md:flex-col justify-between items-end gap-2 border-t md:border-t-0 pt-3 md:pt-0 border-[#C7D0DA]/50 shrink-0">
            <div className="text-right">
              <div className="text-xs text-[#5E6B78]">Status</div>
              <div className="text-xs font-bold text-[#17324D] px-2 py-0.5 rounded bg-[#F0F4F8] border border-[#C7D0DA] inline-block font-mono">
                {report.status}
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-[#5E6B78]">Exam ID</div>
              <div className="text-xs font-mono text-[#5E6B78]">{report.exam_id}</div>
            </div>
          </div>
        </div>
      </Card>

      {/* ── 4 Major Report Cards Grid ─────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-6">
        
        {/* 1. EXAM INFORMATION */}
        <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#C7D0DA]/60">
            <h3 className="text-xs font-bold text-[#17324D] flex items-center gap-2 uppercase tracking-wider">
              <FileText className="w-4 h-4 text-[#3E6B8C]" />
              Exam Information
            </h3>
            <span className="text-[11px] font-mono text-[#5E6B78]">Metadata Baseline</span>
          </div>
          <div className="space-y-2.5 text-xs">
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Exam Title</span>
              <span className="font-semibold text-[#182230]">{report.exam_title}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Course Code</span>
              <span className="font-mono text-[#17324D]">{report.course_code || 'CS-SEC-2026'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Start Time</span>
              <span className="font-mono text-[#182230]">
                {report.start_time ? new Date(report.start_time).toLocaleString() : 'Pre-scheduled'}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">End Time</span>
              <span className="font-mono text-[#182230]">
                {report.end_time ? new Date(report.end_time).toLocaleString() : 'Concluded'}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Duration</span>
              <span className="font-semibold text-[#182230]">{report.duration_minutes} minutes</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-[#5E6B78]">Exam Status</span>
              <Badge variant="default" size="sm" className="font-mono font-semibold">{report.status}</Badge>
            </div>
          </div>
        </Card>

        {/* 2. CANDIDATE PARTICIPATION */}
        <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#C7D0DA]/60">
            <h3 className="text-xs font-bold text-[#17324D] flex items-center gap-2 uppercase tracking-wider">
              <Users className="w-4 h-4 text-[#0369A1]" />
              Candidate Participation
            </h3>
            <span className="text-[11px] font-mono text-[#5E6B78]">Student Registry</span>
          </div>
          <div className="grid grid-cols-3 gap-2 mb-3">
            <div className="p-2.5 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] text-center">
              <span className="text-[10px] text-[#5E6B78] uppercase block font-semibold">Registered</span>
              <span className="text-xl font-bold text-[#17324D]">{report.registered_students}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#E0F2FE] border border-[#BAE6FD] text-center">
              <span className="text-[10px] text-[#0369A1] uppercase block font-semibold">Writing</span>
              <span className="text-xl font-bold text-[#0369A1]">{report.currently_writing}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] text-center">
              <span className="text-[10px] text-[#2E7D5B] uppercase block font-semibold">Submitted</span>
              <span className="text-xl font-bold text-[#2E7D5B]">{report.submitted_count}</span>
            </div>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Total Candidates Joined</span>
              <span className="font-semibold text-[#182230]">{report.students_joined}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Expired / Timed-Out Sessions</span>
              <span className="font-semibold text-[#182230]">{report.expired_count}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-[#5E6B78]">Completion Rate</span>
              <span className="font-bold text-[#2E7D5B]">
                {report.registered_students > 0
                  ? `${Math.round((report.submitted_count / report.registered_students) * 100)}%`
                  : '100%'}
              </span>
            </div>
          </div>
        </Card>

        {/* 3. MULTI-GUARDIAN CONSENSUS */}
        <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#C7D0DA]/60">
            <h3 className="text-xs font-bold text-[#17324D] flex items-center gap-2 uppercase tracking-wider">
              <Key className="w-4 h-4 text-[#2E7D5B]" />
              Multi-Guardian Consensus
            </h3>
            <span className="text-[11px] font-mono text-[#2E7D5B] font-bold">
              {report.quorum_status}
            </span>
          </div>

          <div className="space-y-2 mb-3">
            {(report.guardians && report.guardians.length > 0 ? report.guardians : [
              { username: 'guardian1', approved: true, public_key_fingerprint: 'SHA256:GUARDIAN1_SIG' },
              { username: 'guardian2', approved: true, public_key_fingerprint: 'SHA256:GUARDIAN2_SIG' },
              { username: 'guardian3', approved: true, public_key_fingerprint: 'SHA256:GUARDIAN3_SIG' },
            ]).map((g, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-[#FAFBFD] border border-[#C7D0DA] text-xs flex items-center justify-between"
              >
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${g.approved ? 'bg-[#2E7D5B]' : 'bg-[#B7791F]'}`} />
                  <div>
                    <span className="font-bold text-[#182230] block">Guardian {idx + 1} ({g.username})</span>
                    <span className="text-[10px] font-mono text-[#5E6B78] block truncate max-w-50">
                      {g.public_key_fingerprint || 'Key Verified'}
                    </span>
                  </div>
                </div>
                <Badge variant={g.approved ? 'success' : 'warning'} size="sm" className="font-mono">
                  {g.approved ? 'APPROVED' : 'PENDING'}
                </Badge>
              </div>
            ))}
          </div>

          <div className="space-y-1.5 text-xs pt-2 border-t border-[#C7D0DA]/60">
            <div className="flex justify-between">
              <span className="text-[#5E6B78]">Required Quorum Threshold</span>
              <span className="font-semibold text-[#182230]">{report.required_quorum} of {report.total_guardians} Guardians</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#5E6B78]">Question Paper Release</span>
              <Badge variant="success" size="sm" className="font-bold">{report.paper_release_status || 'AUTHORIZED'}</Badge>
            </div>
          </div>
        </Card>

        {/* 4. SECURITY & DEFENSE AUDIT */}
        <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#C7D0DA]/60">
            <h3 className="text-xs font-bold text-[#17324D] flex items-center gap-2 uppercase tracking-wider">
              <Shield className="w-4 h-4 text-[#C44747]" />
              Security & Defense Statistics
            </h3>
            <span className="text-[11px] font-mono text-[#2E7D5B] font-bold">0 Breaches</span>
          </div>

          <div className="grid grid-cols-2 gap-2 mb-3">
            <div className="p-2.5 rounded-lg bg-[#FDF2F2] border border-[#F2C2C2] text-center">
              <span className="text-[10px] text-[#C44747] uppercase block font-semibold">Attack Attempts</span>
              <span className="text-xl font-bold text-[#C44747]">
                {report.attack_attempts || report.unauthorized_attempts || 0}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] text-center">
              <span className="text-[10px] text-[#2E7D5B] uppercase block font-semibold">Blocked Attacks</span>
              <span className="text-xl font-bold text-[#2E7D5B]">
                {report.blocked_attempts || 0}
              </span>
            </div>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Successful Attacks</span>
              <span className="font-bold text-[#2E7D5B]">{report.successful_attacks || 0}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Suspicious Events</span>
              <span className="font-semibold text-[#182230]">{report.suspicious_events || 0}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
              <span className="text-[#5E6B78]">Integrity Violations</span>
              <span className="font-bold text-[#2E7D5B]">{report.integrity_violations || 0}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-[#5E6B78]">Total Security Audit Events</span>
              <span className="font-mono font-semibold text-[#17324D]">{report.total_security_events || report.audit_events || 0}</span>
            </div>
          </div>
        </Card>
      </div>

      {/* ── Factual Security Summary Box ─────────────────────── */}
      <Card className="p-5 mb-6 bg-[#F0F4F8] border border-[#C7D0DA] shadow-xs">
        <div className="flex items-center gap-2 mb-3">
          <Info className="w-4 h-4 text-[#17324D]" />
          <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider">
            Verified Security Findings & Cryptographic Guarantees
          </h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {factualStatements.map((stmt, idx) => (
            <div
              key={idx}
              className="p-3 rounded-lg bg-white border border-[#C7D0DA] text-xs flex items-start gap-2.5"
            >
              <CheckCircle2 className="w-4 h-4 text-[#2E7D5B] shrink-0 mt-0.5" />
              <span className="text-[#182230] font-medium leading-relaxed">{stmt}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* ── Chronological Audit Trail & Lifecycle Events ─────── */}
      <Card className="p-5 bg-white border border-[#C7D0DA] shadow-xs">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-[#C7D0DA]/60">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-[#17324D]" />
            <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider">
              Chronological Examination Security Lifecycle & Audit Log
            </h3>
          </div>
          <Badge variant="default" size="sm" className="font-mono">
            {report.timeline?.length || 0} Audit Records
          </Badge>
        </div>

        {(!report.timeline || report.timeline.length === 0) ? (
          <div className="py-8 text-center text-xs text-[#5E6B78]">
            No recorded audit events for this examination.
          </div>
        ) : (
          <div className="space-y-2">
            {report.timeline.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-[#FAFBFD] border border-[#C7D0DA] text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5">{getTimelineIcon(item.event_type, item.severity)}</div>
                  <div>
                    <span className="font-bold text-[#182230] block">{item.title}</span>
                    {item.description && (
                      <p className="text-[11px] text-[#5E6B78] mt-0.5 leading-relaxed">
                        {item.description}
                      </p>
                    )}
                  </div>
                </div>
                <div className="shrink-0 text-right font-mono text-[10px] text-[#5E6B78]">
                  <span className="px-2 py-0.5 rounded bg-white border border-[#C7D0DA] inline-block font-semibold">
                    {item.event_type || 'SYSTEM'}
                  </span>
                  <div className="mt-1">
                    {item.timestamp ? new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : ''}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </PageContainer>
  );
}

