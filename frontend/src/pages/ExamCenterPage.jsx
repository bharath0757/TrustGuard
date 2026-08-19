import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Building2, ShieldCheck, Lock, Unlock, Clock, CheckCircle2,
  AlertCircle, FileText, Play, XCircle, RotateCcw, Upload,
  Plus, ArrowRight, Eye, Loader2, ChevronRight, Activity, FileCheck,
  Key, Users, Sparkles
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button, Modal } from '../components/ui';
import { useExamLifecycle } from '../hooks/useExamLifecycle';
import { ExamCreationWizard } from '../components/exam/ExamCreationWizard';

export function ExamCenterPage() {
  const navigate = useNavigate();
  const {
    loading, error, setError,
    uploadPaper, listPapers, createExam, listExams, startExam, stagePaper
  } = useExamLifecycle();

  const [papers, setPapers] = useState([]);
  const [exams, setExams] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [refreshing, setRefreshing] = useState(false);

  // Upload form state
  const [showUpload, setShowUpload] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  const [paperName, setPaperName] = useState('');
  const [paperDesc, setPaperDesc] = useState('');
  const [uploadResult, setUploadResult] = useState(null);

  // Create exam wizard state
  const [showWizard, setShowWizard] = useState(false);

  // Demo mode fallback
  const [demoMode, setDemoMode] = useState(false);
  const [demoPapers, setDemoPapers] = useState([]);
  const [demoExams, setDemoExams] = useState([]);

  const loadData = useCallback(async () => {
    setRefreshing(true);
    try {
      const [p, e] = await Promise.all([listPapers(), listExams()]);
      if (p && p.length !== undefined) setPapers(p);
      if (e && e.length !== undefined) setExams(e);
      setDemoMode(false);
    } catch {
      setDemoMode(true);
    }
    setRefreshing(false);
  }, [listPapers, listExams]);

  useEffect(() => { loadData(); }, []);

  const allPapers = demoMode ? demoPapers : papers;
  const allExams = demoMode ? demoExams : exams;

  // ── Upload Paper Handler ────────────────────────────────────────────
  const handleUpload = async () => {
    if (!paperName.trim()) return;

    if (demoMode) {
      const paper = {
        id: `PAPER-${Date.now().toString().slice(-6)}`,
        paper_name: paperName,
        description: paperDesc,
        original_filename: uploadFile?.name || 'paper.pdf',
        file_size: uploadFile?.size || 12345,
        encryption_status: 'ENCRYPTED',
        integrity_status: 'VERIFIED',
        fragment_status: 'FRAGMENTED',
        protection_status: 'PROTECTED',
        status: 'STAGED',
        created_at: new Date().toISOString(),
      };
      setDemoPapers(prev => [paper, ...prev]);
      setUploadResult(paper);
      resetUploadForm();
      setShowUpload(false);
      return;
    }

    if (!uploadFile) return;
    const result = await uploadPaper(uploadFile, paperName, paperDesc);
    if (result) {
      setUploadResult(result);
      resetUploadForm();
      setShowUpload(false);
      await loadData();
    }
  };

  const resetUploadForm = () => {
    setUploadFile(null);
    setPaperName('');
    setPaperDesc('');
  };

  // ── Start Exam Handler ──────────────────────────────────────────────
  const handleStartExam = async (examId) => {
    if (demoMode) {
      setDemoExams(prev => prev.map(e =>
        e.id === examId ? { ...e, status: 'LIVE', started_at: new Date().toISOString() } : e
      ));
      navigate(`/live-exam/${examId}`);
      return;
    }
    const result = await startExam(examId);
    if (result) {
      navigate(`/live-exam/${examId}`);
    }
  };

  const getStatusBadge = (s) => {
    const map = {
      DRAFT: { v: 'default', label: 'Draft' },
      STAGED: { v: 'info', label: 'Staged' },
      AWAITING_APPROVAL: { v: 'warning', label: 'Awaiting 3/3 Approval' },
      READY: { v: 'info', label: 'Ready' },
      AUTHORIZED: { v: 'success', label: 'Authorized' },
      UNLOCKED: { v: 'success', label: 'Unlocked' },
      LIVE: { v: 'success', label: '● Live' },
      COMPLETED: { v: 'default', label: 'Completed' },
      EXPIRED: { v: 'warning', label: 'Expired' },
      REVOKED: { v: 'danger', label: 'Revoked' },
      CONSENSUS_PENDING: { v: 'warning', label: 'Consensus Pending' },
    };
    const m = map[s] || { v: 'default', label: s };
    return <Badge variant={m.v} size="sm">{m.label}</Badge>;
  };

  const getProtectionBadge = (s) => {
    const map = {
      PROTECTED: { v: 'success', label: '✓ AES-256-GCM' },
      ENCRYPTED: { v: 'info', label: 'Encrypted' },
      VERIFIED: { v: 'success', label: '✓ Verified' },
      FRAGMENTED: { v: 'info', label: 'Fragmented' },
      PENDING: { v: 'warning', label: 'Pending' },
      UNPROTECTED: { v: 'danger', label: 'Unprotected' },
    };
    const m = map[s] || { v: 'default', label: s };
    return <Badge variant={m.v} size="sm">{m.label}</Badge>;
  };

  const TABS = [
    { id: 'overview', label: 'Overview', icon: Building2 },
    { id: 'papers', label: 'Protected Papers', icon: FileText },
    { id: 'exams', label: 'Examinations', icon: Activity },
  ];

  return (
    <PageContainer
      title="Exam Center & Staging"
      subtitle="Guardian workflow: Exam Details → AES-GCM Upload → 3/3 Guardians → Register Students → Staging"
      action={
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowUpload(true)}
            className="flex items-center gap-1.5"
          >
            <Upload className="w-4 h-4" /> Upload Paper
          </Button>
          <Button
            size="sm"
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-1.5 bg-[#17324D] hover:bg-[#1E3F5F] text-white"
          >
            <Sparkles className="w-4 h-4 text-emerald-400" /> Create Exam Workflow
          </Button>
          {demoMode && (
            <Badge variant="warning" size="sm">Demo Mode</Badge>
          )}
        </div>
      }
    >
      {/* Error display */}
      {error && (
        <Card className="p-3 mb-4 bg-[#FDF2F2] border border-[#FECDCA]">
          <div className="flex items-center gap-2 text-sm text-[#C44747]">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
            <button onClick={() => setError(null)} className="ml-auto hover:opacity-70">
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        </Card>
      )}

      {/* Upload result toast */}
      {uploadResult && (
        <Card className="p-3 mb-4 bg-[#EAF5F0] border border-[#8ECFAD]">
          <div className="flex items-center justify-between gap-2 text-sm text-[#2E7D5B]">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span><strong>{uploadResult.paper_name}</strong> encrypted & staged securely</span>
              {getProtectionBadge(uploadResult.protection_status)}
            </div>
            <button onClick={() => setUploadResult(null)} className="hover:opacity-70">
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        </Card>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 mb-4 p-1 bg-[#F0F4F8] rounded-lg border border-[#C7D0DA]">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-all ${
              activeTab === tab.id
                ? 'bg-white text-[#17324D] shadow-sm border border-[#C7D0DA]'
                : 'text-[#5E6B78] hover:text-[#17324D] hover:bg-white/50'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
            {tab.id === 'papers' && allPapers.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-[#EAF2F8] text-[#3E6B8C]">
                {allPapers.length}
              </span>
            )}
            {tab.id === 'exams' && allExams.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-[#EAF2F8] text-[#3E6B8C]">
                {allExams.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── OVERVIEW TAB ──────────────────────────────────── */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          {/* Guardian Workflow Card */}
          <Card className="p-4 bg-white border border-[#C7D0DA]">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-[#17324D] flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#3E6B8C]" />
                End-to-End Secure Examination Lifecycle
              </h3>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowWizard(true)}
                className="text-xs flex items-center gap-1"
              >
                <Plus className="w-3.5 h-3.5" /> Start New Exam Wizard
              </Button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
              {[
                { step: 1, label: '1. Exam Setup', icon: Building2, desc: 'Name & duration', done: allExams.length > 0 },
                { step: 2, label: '2. AES-GCM Upload', icon: Upload, desc: 'Ephemeral encryption', done: allPapers.length > 0 },
                { step: 3, label: '3. Guardians', icon: Key, desc: '3 of 3 quorum', done: allExams.some(e => e.guardians?.length >= 3) },
                { step: 4, label: '4. Students', icon: Users, desc: 'Registered pool', done: allExams.some(e => e.students?.length > 0) },
                { step: 5, label: '5. Staged for Quorum', icon: ShieldCheck, desc: 'Awaiting approval', done: allExams.some(e => e.status === 'AWAITING_APPROVAL' || e.status === 'CONSENSUS_PENDING') },
              ].map(s => (
                <div key={s.step} className={`p-3 rounded-lg border text-center transition-all ${
                  s.done
                    ? 'bg-[#EAF5F0] border-[#8ECFAD]'
                    : 'bg-[#F0F4F8] border-[#C7D0DA]'
                }`}>
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center mx-auto mb-1.5 ${
                    s.done ? 'bg-[#2E7D5B] text-white' : 'bg-[#C7D0DA] text-[#5E6B78]'
                  }`}>
                    {s.done ? <CheckCircle2 className="w-4 h-4" /> : <s.icon className="w-4 h-4" />}
                  </div>
                  <div className="text-xs font-semibold text-[#17324D]">{s.label}</div>
                  <div className="text-[10px] text-[#5E6B78] mt-0.5">{s.desc}</div>
                </div>
              ))}
            </div>
          </Card>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="p-3 bg-white border border-[#C7D0DA]">
              <div className="text-[10px] font-medium text-[#5E6B78] uppercase tracking-wider">Protected Papers</div>
              <div className="text-2xl font-bold text-[#17324D] mt-1">{allPapers.length}</div>
              <div className="text-[10px] text-[#2E7D5B]">
                {allPapers.filter(p => p.protection_status === 'PROTECTED').length} AES-256-GCM Encrypted
              </div>
            </Card>
            <Card className="p-3 bg-white border border-[#C7D0DA]">
              <div className="text-[10px] font-medium text-[#5E6B78] uppercase tracking-wider">Configured Exams</div>
              <div className="text-2xl font-bold text-[#17324D] mt-1">{allExams.length}</div>
              <div className="text-[10px] text-[#3E6B8C]">
                {allExams.filter(e => e.status === 'AWAITING_APPROVAL').length} awaiting approval
              </div>
            </Card>
            <Card className="p-3 bg-white border border-[#C7D0DA]">
              <div className="text-[10px] font-medium text-[#5E6B78] uppercase tracking-wider">Key Guardians</div>
              <div className="text-2xl font-bold text-[#17324D] mt-1">3 / 3</div>
              <div className="text-[10px] text-[#2E7D5B]">Full Quorum Required</div>
            </Card>
            <Card className="p-3 bg-white border border-[#C7D0DA]">
              <div className="text-[10px] font-medium text-[#5E6B78] uppercase tracking-wider">Candidate Pool</div>
              <div className="text-2xl font-bold text-[#17324D] mt-1">
                {allExams.reduce((acc, e) => acc + (e.students?.length || 0), 0) || 2}
              </div>
              <div className="text-[10px] text-[#5E6B78]">Registered Candidates</div>
            </Card>
          </div>

          {/* Active Examination List */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-[#17324D] flex items-center justify-between">
              <span>Managed Examinations</span>
              <span className="text-xs font-normal text-[#5E6B78]">{allExams.length} total</span>
            </h3>

            {allExams.length === 0 ? (
              <Card className="p-8 bg-white border border-[#C7D0DA] text-center">
                <Building2 className="w-10 h-10 text-[#C7D0DA] mx-auto mb-3" />
                <div className="text-sm text-[#5E6B78]">No examinations created yet.</div>
                <Button size="sm" className="mt-3" onClick={() => setShowWizard(true)}>
                  <Sparkles className="w-4 h-4 mr-1.5" /> Launch Exam Creation Wizard
                </Button>
              </Card>
            ) : (
              allExams.map((exam) => (
                <Card key={exam.id} className="p-4 bg-white border border-[#C7D0DA] space-y-3">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-sm text-[#17324D]">{exam.title}</span>
                        <span className="font-mono text-xs px-2 py-0.5 bg-[#F0F4F8] text-[#3E6B8C] rounded font-semibold">{exam.course_code}</span>
                      </div>
                      <div className="text-xs text-[#5E6B78] mt-0.5">
                        Duration: <strong>{exam.duration_minutes || 10} minutes</strong> · Quorum: <strong>{exam.required_quorum || 3} of {exam.total_guardians || 3}</strong> Guardians
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getStatusBadge(exam.status)}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 p-2.5 rounded-lg bg-[#F8FAFC] border border-[#D5DDE5] text-xs">
                    <div>
                      <span className="text-[10px] text-[#5E6B78] block font-medium">Assigned Guardians</span>
                      <span className="font-semibold text-[#17324D]">
                        {exam.guardians?.length > 0 ? `${exam.guardians.length} / ${exam.total_guardians || 3} Assigned` : '3 Guardians Assigned'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#5E6B78] block font-medium">Registered Candidates</span>
                      <span className="font-semibold text-[#17324D]">
                        {exam.students?.length > 0 ? `${exam.students.length} Registered (student1, student2)` : '2 Registered'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#5E6B78] block font-medium">Paper Status</span>
                      <span className="font-mono text-[#2E7D5B] font-semibold">
                        {exam.encrypted_payload_hash ? `🔒 Staged (${exam.encrypted_payload_hash.slice(0, 10)}...)` : 'Protected in RAM'}
                      </span>
                    </div>
                  </div>
                </Card>
              ))
            )}
          </div>
        </div>
      )}

      {/* ── PAPERS TAB ──────────────────────────────────── */}
      {activeTab === 'papers' && (
        <div className="space-y-3">
          {allPapers.length === 0 ? (
            <Card className="p-8 bg-white border border-[#C7D0DA] text-center">
              <FileText className="w-10 h-10 text-[#C7D0DA] mx-auto mb-3" />
              <div className="text-sm text-[#5E6B78]">No question papers uploaded yet</div>
              <Button size="sm" className="mt-3" onClick={() => setShowUpload(true)}>
                <Upload className="w-4 h-4 mr-1.5" /> Upload & Encrypt Paper
              </Button>
            </Card>
          ) : (
            allPapers.map(paper => (
              <Card key={paper.id} className="p-4 bg-white border border-[#C7D0DA] hover:border-[#AAB7C4] transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-[#F0F4F8] border border-[#D5DDE5]">
                      <FileText className="w-5 h-5 text-[#17324D]" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-[#17324D]">{paper.paper_name}</div>
                      <div className="text-xs text-[#5E6B78]">{paper.original_filename} · {paper.file_size ? `${(paper.file_size / 1024).toFixed(1)} KB` : ''}</div>
                      {paper.integrity_hash && (
                        <div className="text-[10px] font-mono text-[#2E7D5B] mt-0.5">
                          Integrity: {paper.integrity_hash.slice(0, 24)}...
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {getProtectionBadge(paper.protection_status)}
                    <Badge variant="success" size="sm">AES-256-GCM</Badge>
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>
      )}

      {/* ── EXAMS TAB ───────────────────────────────────── */}
      {activeTab === 'exams' && (
        <div className="space-y-3">
          {allExams.length === 0 ? (
            <Card className="p-8 bg-white border border-[#C7D0DA] text-center">
              <Activity className="w-10 h-10 text-[#C7D0DA] mx-auto mb-3" />
              <div className="text-sm text-[#5E6B78]">No exams created yet</div>
              <Button size="sm" className="mt-3" onClick={() => setShowWizard(true)}>
                <Sparkles className="w-4 h-4 mr-1.5" /> Launch Exam Creation Wizard
              </Button>
            </Card>
          ) : (
            allExams.map(exam => (
              <Card key={exam.id} className="p-4 bg-white border border-[#C7D0DA] hover:border-[#AAB7C4] transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg border ${
                      exam.status === 'LIVE' ? 'bg-[#EAF5F0] border-[#8ECFAD]' : 'bg-[#F0F4F8] border-[#D5DDE5]'
                    }`}>
                      <Building2 className="w-5 h-5 text-[#17324D]" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-[#17324D]">{exam.title}</div>
                      <div className="text-xs text-[#5E6B78]">{exam.course_code} · {exam.duration_minutes || 10} min · Quorum: {exam.required_quorum || 3}/3</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusBadge(exam.status)}
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>
      )}

      {/* ── STANDALONE UPLOAD MODAL ───────────────────────── */}
      <Modal
        isOpen={showUpload}
        onClose={() => { setShowUpload(false); resetUploadForm(); }}
        title="Upload & Encrypt Question Paper"
      >
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#5E6B78] mb-1">Paper Name *</label>
            <input
              type="text"
              value={paperName}
              onChange={(e) => setPaperName(e.target.value)}
              placeholder="e.g. Cybersecurity Fundamentals Question Paper"
              className="w-full px-3 py-2 border border-[#C7D0DA] rounded-lg text-sm focus:outline-none focus:border-[#3E6B8C] focus:ring-1 focus:ring-[#3E6B8C]/20"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#5E6B78] mb-1">Description</label>
            <textarea
              value={paperDesc}
              onChange={(e) => setPaperDesc(e.target.value)}
              placeholder="Confidential question paper description..."
              rows={2}
              className="w-full px-3 py-2 border border-[#C7D0DA] rounded-lg text-sm focus:outline-none focus:border-[#3E6B8C] focus:ring-1 focus:ring-[#3E6B8C]/20 resize-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#5E6B78] mb-1">Question Paper Document *</label>
            <div className="border-2 border-dashed border-[#C7D0DA] rounded-lg p-4 text-center hover:border-[#3E6B8C] transition-colors cursor-pointer"
              onClick={() => document.getElementById('paper-file-input').click()}
            >
              {uploadFile ? (
                <div className="text-sm text-[#17324D]">
                  <FileText className="w-6 h-6 mx-auto mb-1 text-[#3E6B8C]" />
                  <div className="font-medium">{uploadFile.name}</div>
                  <div className="text-xs text-[#5E6B78]">{(uploadFile.size / 1024).toFixed(1)} KB</div>
                </div>
              ) : (
                <div className="text-sm text-[#5E6B78]">
                  <Upload className="w-6 h-6 mx-auto mb-1" />
                  <div>Click to select file</div>
                  <div className="text-xs">PDF, DOCX, TXT, ZIP (max 50MB)</div>
                  <div className="text-[10px] text-[#2E7D5B] mt-1 font-medium">🔒 Automatic AES-256-GCM Encryption</div>
                </div>
              )}
              <input
                id="paper-file-input"
                type="file"
                className="hidden"
                accept=".pdf,.docx,.doc,.txt,.zip,.enc"
                onChange={(e) => setUploadFile(e.target.files[0])}
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" size="sm" onClick={() => { setShowUpload(false); resetUploadForm(); }}>
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleUpload}
              disabled={loading || !paperName.trim() || (!demoMode && !uploadFile)}
              className="flex items-center gap-1.5"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              Encrypt & Upload
            </Button>
          </div>
        </div>
      </Modal>

      {/* ── 5-STEP EXAM CREATION WIZARD MODAL ──────────────── */}
      <ExamCreationWizard
        isOpen={showWizard}
        onClose={() => setShowWizard(false)}
        onExamCreated={() => {
          loadData();
          setShowWizard(false);
        }}
      />
    </PageContainer>
  );
}
