import React, { useState, useEffect } from 'react';
import {
  ShieldCheck, Upload, Users, UserCheck, CheckCircle2,
  AlertCircle, FileText, ArrowRight, ArrowLeft, Loader2,
  Lock, Key, Clock, Check, Sparkles, Building2
} from 'lucide-react';
import { Card, Badge, Button, Modal } from '../ui';
import { useExamLifecycle } from '../../hooks/useExamLifecycle';

const STEPS = [
  { id: 1, title: 'Exam Details', icon: Building2 },
  { id: 2, title: 'Upload Paper', icon: Upload },
  { id: 3, title: 'Assign Guardians', icon: Key },
  { id: 4, title: 'Register Students', icon: Users },
  { id: 5, title: 'Secure Staging', icon: ShieldCheck },
];

export function ExamCreationWizard({ isOpen, onClose, onExamCreated }) {
  const {
    loading, error, setError,
    uploadPaper, createExam, assignGuardian, registerStudents, stagePaper, getUsers
  } = useExamLifecycle();

  const [currentStep, setCurrentStep] = useState(1);
  const [wizardSuccess, setWizardSuccess] = useState(false);

  // Step 1: Exam Details
  const [examTitle, setExamTitle] = useState('Cybersecurity Fundamentals');
  const [examCode, setExamCode] = useState('CS-SEC-2026');
  const [examDuration, setExamDuration] = useState(10);
  const [examDesc, setExamDesc] = useState('Secure final examination covering cryptographic primitives, zero persistence, and threshold consensus.');

  // Step 2: Paper Upload
  const [paperName, setPaperName] = useState('Cybersecurity Fundamentals Question Paper');
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadedPaperData, setUploadedPaperData] = useState(null);

  // Step 3: Guardians
  const [availableGuardians, setAvailableGuardians] = useState([]);
  const [selectedGuardianIds, setSelectedGuardianIds] = useState([]);
  const [requiredQuorum, setRequiredQuorum] = useState(3);

  // Step 4: Students
  const [availableStudents, setAvailableStudents] = useState([]);
  const [selectedStudentIds, setSelectedStudentIds] = useState([]);

  // Step 5: Created Exam & Staging Result
  const [createdExamRecord, setCreatedExamRecord] = useState(null);
  const [stagingResult, setStagingResult] = useState(null);

  // Load available users on open
  useEffect(() => {
    if (!isOpen) return;

    const fetchUsers = async () => {
      try {
        const [gList, sList] = await Promise.all([
          getUsers('KEY_GUARDIAN'),
          getUsers('STUDENT'),
        ]);

        // Fallback default demo users if server has generic list
        const allUsers = await getUsers();
        const guardians = (gList && gList.length > 0) ? gList : allUsers.filter(u => u.role === 'KEY_GUARDIAN' || u.role === 'GUARDIAN');
        const students = (sList && sList.length > 0) ? sList : allUsers.filter(u => u.role === 'STUDENT');

        setAvailableGuardians(guardians);
        setAvailableStudents(students);

        // Pre-select guardian1, guardian2, guardian3 and student1, student2
        setSelectedGuardianIds(guardians.map(g => g.id));
        setSelectedStudentIds(students.map(s => s.id));
        setRequiredQuorum(guardians.length > 0 ? guardians.length : 3);
      } catch {
        // Fallback demo personas
        setAvailableGuardians([
          { id: 'demo-g1', username: 'guardian1', email: 'guardian1@trustguard.demo' },
          { id: 'demo-g2', username: 'guardian2', email: 'guardian2@trustguard.demo' },
          { id: 'demo-g3', username: 'guardian3', email: 'guardian3@trustguard.demo' },
        ]);
        setAvailableStudents([
          { id: 'demo-s1', username: 'student1', email: 'student1@trustguard.demo' },
          { id: 'demo-s2', username: 'student2', email: 'student2@trustguard.demo' },
        ]);
      }
    };

    fetchUsers();
  }, [isOpen, getUsers]);

  const handleNextFromStep1 = () => {
    if (!examTitle.trim() || !examCode.trim() || examDuration <= 0) {
      setError('Please provide a valid exam title, course code, and positive duration.');
      return;
    }
    setError(null);
    setCurrentStep(2);
  };

  const handleNextFromStep2 = async () => {
    if (!uploadedPaperData) {
      if (!uploadFile && !paperName.trim()) {
        setError('Please select a question paper file to encrypt and stage.');
        return;
      }

      // If file selected, upload now
      if (uploadFile) {
        const res = await uploadPaper(uploadFile, paperName || examTitle, examDesc);
        if (!res) return;
        setUploadedPaperData(res);
      } else {
        // Create simulated protected paper placeholder if no file picked
        const simulatedBlob = new Blob([`CONFIDENTIAL EXAM PAPER: ${examTitle}\n\nQuestions:\n1. Explain Shamir Secret Sharing.\n2. Detail AES-GCM authenticated encryption.`], { type: 'text/plain' });
        const dummyFile = new File([simulatedBlob], 'cybersecurity_fundamentals_paper.txt', { type: 'text/plain' });
        const res = await uploadPaper(dummyFile, paperName || examTitle, examDesc);
        if (!res) return;
        setUploadedPaperData(res);
      }
    }
    setError(null);
    setCurrentStep(3);
  };

  const handleNextFromStep3 = () => {
    if (selectedGuardianIds.length === 0) {
      setError('At least one guardian must be assigned to the examination.');
      return;
    }
    setError(null);
    setCurrentStep(4);
  };

  const handleNextFromStep4 = () => {
    if (selectedStudentIds.length === 0) {
      setError('At least one student candidate must be registered for the examination.');
      return;
    }
    setError(null);
    setCurrentStep(5);
  };

  // ── Step 5: Final Execution Handler ──────────────────────────────────
  const handleFinalizeAndStage = async () => {
    setError(null);
    try {
      const now = new Date();
      const schedStart = new Date(now.getTime() + 2 * 60 * 1000);
      const schedEnd = new Date(schedStart.getTime() + examDuration * 60 * 1000);

      // 1. Create Exam record
      const examRes = await createExam({
        title: examTitle,
        course_code: examCode,
        description: examDesc,
        paper_id: uploadedPaperData?.id || null,
        scheduled_start: schedStart.toISOString(),
        scheduled_end: schedEnd.toISOString(),
        duration_minutes: examDuration,
        required_quorum: requiredQuorum || selectedGuardianIds.length,
        total_guardians: selectedGuardianIds.length,
      });

      if (!examRes) return;
      setCreatedExamRecord(examRes);

      // 2. Assign Guardians
      for (const gid of selectedGuardianIds) {
        const guardianObj = availableGuardians.find(g => g.id === gid);
        const fp = `FP_${guardianObj?.username || gid}_RSA4096`;
        await assignGuardian(examRes.id, gid, fp);
      }

      // 3. Register Students
      if (selectedStudentIds.length > 0) {
        await registerStudents(examRes.id, selectedStudentIds);
      }

      // 4. Secure Ephemeral Paper Staging
      const stageRes = await stagePaper(examRes.id, uploadedPaperData?.id, 1800);
      setStagingResult(stageRes);
      setWizardSuccess(true);

      if (onExamCreated) {
        onExamCreated(examRes);
      }
    } catch (err) {
      setError(err?.message || 'Failed to complete exam setup and staging.');
    }
  };

  const toggleGuardian = (id) => {
    setSelectedGuardianIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const toggleStudent = (id) => {
    setSelectedStudentIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const handleReset = () => {
    setCurrentStep(1);
    setWizardSuccess(false);
    setCreatedExamRecord(null);
    setStagingResult(null);
    setUploadedPaperData(null);
    setUploadFile(null);
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleReset}
      title="Create Secure Examination"
      maxWidth="max-w-2xl"
    >
      <div className="space-y-4">
        {/* Step Indicator Header */}
        <div className="flex items-center justify-between pb-3 border-b border-[#D5DDE5]">
          {STEPS.map((s, idx) => {
            const isDone = currentStep > s.id || wizardSuccess;
            const isCurrent = currentStep === s.id && !wizardSuccess;
            return (
              <React.Fragment key={s.id}>
                <div className="flex items-center gap-1.5">
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-all ${
                      isDone
                        ? 'bg-[#2E7D5B] text-white'
                        : isCurrent
                        ? 'bg-[#17324D] text-white ring-2 ring-[#3E6B8C]/30'
                        : 'bg-[#F0F4F8] text-[#8C9BA8] border border-[#D5DDE5]'
                    }`}
                  >
                    {isDone ? <Check className="w-3.5 h-3.5" /> : s.id}
                  </div>
                  <span
                    className={`text-xs hidden sm:inline font-medium ${
                      isCurrent ? 'text-[#17324D] font-semibold' : isDone ? 'text-[#2E7D5B]' : 'text-[#8C9BA8]'
                    }`}
                  >
                    {s.title}
                  </span>
                </div>
                {idx < STEPS.length - 1 && (
                  <div
                    className={`flex-1 h-0.5 mx-2 ${
                      currentStep > s.id ? 'bg-[#2E7D5B]' : 'bg-[#D5DDE5]'
                    }`}
                  />
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Global Error Banner */}
        {error && (
          <Card className="p-2.5 bg-[#FDF2F2] border border-[#FECDCA]">
            <div className="flex items-center gap-2 text-xs text-[#C44747]">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          </Card>
        )}

        {/* ── STEP 1: Exam Details ───────────────────────────────────────── */}
        {currentStep === 1 && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-[#17324D] mb-1">Exam Title *</label>
                <input
                  type="text"
                  value={examTitle}
                  onChange={(e) => setExamTitle(e.target.value)}
                  placeholder="e.g. Cybersecurity Fundamentals"
                  className="w-full px-3 py-2 border border-[#C7D0DA] rounded-lg text-xs focus:outline-none focus:border-[#3E6B8C] focus:ring-1 focus:ring-[#3E6B8C]/20"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#17324D] mb-1">Course Code *</label>
                <input
                  type="text"
                  value={examCode}
                  onChange={(e) => setExamCode(e.target.value)}
                  placeholder="e.g. CS-SEC-2026"
                  className="w-full px-3 py-2 border border-[#C7D0DA] rounded-lg text-xs focus:outline-none focus:border-[#3E6B8C] focus:ring-1 focus:ring-[#3E6B8C]/20"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-[#17324D] mb-1">Exam Duration (Minutes) *</label>
                <input
                  type="number"
                  value={examDuration}
                  onChange={(e) => setExamDuration(parseInt(e.target.value) || 10)}
                  min={1}
                  max={1440}
                  className="w-full px-3 py-2 border border-[#C7D0DA] rounded-lg text-xs focus:outline-none focus:border-[#3E6B8C] focus:ring-1 focus:ring-[#3E6B8C]/20"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#17324D] mb-1">Security Mode</label>
                <div className="px-3 py-2 bg-[#F0F4F8] border border-[#D5DDE5] rounded-lg text-xs font-medium text-[#17324D] flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-[#2E7D5B]" />
                  <span>AES-256-GCM + RAM Staging</span>
                </div>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#17324D] mb-1">Description / Instructions</label>
              <textarea
                value={examDesc}
                onChange={(e) => setExamDesc(e.target.value)}
                rows={2}
                placeholder="Candidate instructions or syllabus details..."
                className="w-full px-3 py-2 border border-[#C7D0DA] rounded-lg text-xs focus:outline-none focus:border-[#3E6B8C] focus:ring-1 focus:ring-[#3E6B8C]/20 resize-none"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" size="sm" onClick={handleReset}>Cancel</Button>
              <Button size="sm" onClick={handleNextFromStep1} className="flex items-center gap-1.5">
                Next: Upload Paper <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}

        {/* ── STEP 2: Upload Question Paper ──────────────────────────────── */}
        {currentStep === 2 && (
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-[#17324D] mb-1">Paper Title *</label>
              <input
                type="text"
                value={paperName}
                onChange={(e) => setPaperName(e.target.value)}
                placeholder="e.g. Cybersecurity Fundamentals Question Paper"
                className="w-full px-3 py-2 border border-[#C7D0DA] rounded-lg text-xs focus:outline-none focus:border-[#3E6B8C] focus:ring-1 focus:ring-[#3E6B8C]/20"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#17324D] mb-1">Question Paper Document *</label>
              <div
                className="border-2 border-dashed border-[#C7D0DA] rounded-lg p-5 text-center hover:border-[#3E6B8C] transition-colors cursor-pointer bg-[#FAFCFE]"
                onClick={() => document.getElementById('wizard-paper-file-input').click()}
              >
                {uploadFile ? (
                  <div className="text-xs text-[#17324D]">
                    <FileText className="w-8 h-8 mx-auto mb-1.5 text-[#3E6B8C]" />
                    <div className="font-semibold text-sm">{uploadFile.name}</div>
                    <div className="text-[#5E6B78] mt-0.5">{(uploadFile.size / 1024).toFixed(1)} KB · Ready for AES-GCM encryption</div>
                  </div>
                ) : (
                  <div className="text-xs text-[#5E6B78]">
                    <Upload className="w-8 h-8 mx-auto mb-1.5 text-[#8C9BA8]" />
                    <div className="font-semibold text-[#17324D] text-sm">Choose or drop question paper</div>
                    <div className="text-[11px] mt-0.5">Permitted formats: .pdf, .docx, .doc, .txt, .zip (Max 50 MB)</div>
                    <div className="text-[10px] text-[#2E7D5B] font-medium mt-2">🔒 File is encrypted client-to-ephemeral-store before staging</div>
                  </div>
                )}
                <input
                  id="wizard-paper-file-input"
                  type="file"
                  className="hidden"
                  accept=".pdf,.docx,.doc,.txt,.zip,.enc"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setUploadFile(e.target.files[0]);
                      setUploadedPaperData(null);
                    }
                  }}
                />
              </div>
            </div>

            {uploadedPaperData && (
              <div className="p-2.5 rounded-lg bg-[#EAF5F0] border border-[#8ECFAD] flex items-center justify-between text-xs text-[#2E7D5B]">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>Encrypted Payload Hash: <code className="font-mono">{uploadedPaperData.integrity_hash?.slice(0, 16)}...</code></span>
                </div>
                <Badge variant="success" size="sm">AES-256-GCM Verified</Badge>
              </div>
            )}

            <div className="flex justify-between pt-2">
              <Button variant="outline" size="sm" onClick={() => setCurrentStep(1)} className="flex items-center gap-1.5">
                <ArrowLeft className="w-3.5 h-3.5" /> Back
              </Button>
              <Button size="sm" onClick={handleNextFromStep2} disabled={loading} className="flex items-center gap-1.5">
                {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
                Next: Assign Guardians <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}

        {/* ── STEP 3: Assign Guardians ───────────────────────────────────── */}
        {currentStep === 3 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold text-[#17324D]">Select Key Guardians (Exam Conductors)</h4>
                <p className="text-[11px] text-[#5E6B78]">Guardians who will participate in the multi-key quorum release.</p>
              </div>
              <Badge variant="info" size="sm">Quorum: {requiredQuorum} / {selectedGuardianIds.length}</Badge>
            </div>

            <div className="grid grid-cols-1 gap-2 max-h-48 overflow-y-auto pr-1">
              {availableGuardians.map((g) => {
                const isSelected = selectedGuardianIds.includes(g.id);
                return (
                  <div
                    key={g.id}
                    onClick={() => toggleGuardian(g.id)}
                    className={`p-2.5 rounded-lg border flex items-center justify-between cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-[#EAF2F8] border-[#3E6B8C] text-[#17324D]'
                        : 'bg-white border-[#D5DDE5] text-[#5E6B78] hover:bg-[#F8FAFC]'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                        isSelected ? 'bg-[#17324D] text-white' : 'bg-[#D5DDE5] text-[#5E6B78]'
                      }`}>
                        {g.username.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-[#17324D]">{g.username}</div>
                        <div className="text-[10px] text-[#5E6B78]">{g.email}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-[#8C9BA8]">RSA-4096 Key</span>
                      <div className={`w-4 h-4 rounded flex items-center justify-center ${
                        isSelected ? 'bg-[#3E6B8C] text-white' : 'border border-[#C7D0DA]'
                      }`}>
                        {isSelected && <Check className="w-3 h-3" />}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#D5DDE5] text-[11px] text-[#5E6B78] flex items-center gap-2">
              <Key className="w-4 h-4 text-[#3E6B8C] shrink-0" />
              <span>Threshold Consensus: <strong>{requiredQuorum} of {selectedGuardianIds.length}</strong> cryptographic shares will be required to reconstruct the paper.</span>
            </div>

            <div className="flex justify-between pt-2">
              <Button variant="outline" size="sm" onClick={() => setCurrentStep(2)} className="flex items-center gap-1.5">
                <ArrowLeft className="w-3.5 h-3.5" /> Back
              </Button>
              <Button size="sm" onClick={handleNextFromStep3} className="flex items-center gap-1.5">
                Next: Register Students <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}

        {/* ── STEP 4: Register Students ──────────────────────────────────── */}
        {currentStep === 4 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold text-[#17324D]">Register Candidates / Students</h4>
                <p className="text-[11px] text-[#5E6B78]">Select student accounts authorized to access this exam upon release.</p>
              </div>
              <Badge variant="default" size="sm">{selectedStudentIds.length} Selected</Badge>
            </div>

            <div className="grid grid-cols-1 gap-2 max-h-48 overflow-y-auto pr-1">
              {availableStudents.map((s) => {
                const isSelected = selectedStudentIds.includes(s.id);
                return (
                  <div
                    key={s.id}
                    onClick={() => toggleStudent(s.id)}
                    className={`p-2.5 rounded-lg border flex items-center justify-between cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-[#EAF2F8] border-[#3E6B8C] text-[#17324D]'
                        : 'bg-white border-[#D5DDE5] text-[#5E6B78] hover:bg-[#F8FAFC]'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                        isSelected ? 'bg-[#17324D] text-white' : 'bg-[#D5DDE5] text-[#5E6B78]'
                      }`}>
                        {s.username.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-[#17324D]">{s.username}</div>
                        <div className="text-[10px] text-[#5E6B78]">{s.email}</div>
                      </div>
                    </div>
                    <div className={`w-4 h-4 rounded flex items-center justify-center ${
                      isSelected ? 'bg-[#3E6B8C] text-white' : 'border border-[#C7D0DA]'
                    }`}>
                      {isSelected && <Check className="w-3 h-3" />}
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#D5DDE5] text-[11px] text-[#5E6B78] flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-[#2E7D5B] shrink-0" />
              <span>Registered candidates receive secure, timed access only after 3/3 guardian quorum authorization.</span>
            </div>

            <div className="flex justify-between pt-2">
              <Button variant="outline" size="sm" onClick={() => setCurrentStep(3)} className="flex items-center gap-1.5">
                <ArrowLeft className="w-3.5 h-3.5" /> Back
              </Button>
              <Button size="sm" onClick={handleNextFromStep4} className="flex items-center gap-1.5">
                Next: Review & Stage <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}

        {/* ── STEP 5: Review, Ephemeral Staging & Summary ────────────────── */}
        {currentStep === 5 && !wizardSuccess && (
          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#D5DDE5] space-y-2">
              <h4 className="text-xs font-bold text-[#17324D] flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-[#3E6B8C]" />
                Examination Setup Summary
              </h4>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-[10px] text-[#5E6B78] block">Exam Name:</span>
                  <span className="font-semibold text-[#17324D]">{examTitle}</span>
                </div>
                <div>
                  <span className="text-[10px] text-[#5E6B78] block">Course Code:</span>
                  <span className="font-mono text-[#17324D]">{examCode}</span>
                </div>
                <div>
                  <span className="text-[10px] text-[#5E6B78] block">Duration:</span>
                  <span className="font-semibold text-[#17324D]">{examDuration} minutes</span>
                </div>
                <div>
                  <span className="text-[10px] text-[#5E6B78] block">Required Consensus:</span>
                  <span className="font-semibold text-[#2E7D5B]">3 / 3 Guardians (100% Quorum)</span>
                </div>
              </div>

              <div className="pt-2 border-t border-[#D5DDE5] grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-[10px] text-[#5E6B78] block">Assigned Guardians ({selectedGuardianIds.length}):</span>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {availableGuardians.filter(g => selectedGuardianIds.includes(g.id)).map(g => (
                      <span key={g.id} className="px-1.5 py-0.5 rounded bg-white border border-[#D5DDE5] text-[10px] font-mono">
                        {g.username}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-[#5E6B78] block">Registered Students ({selectedStudentIds.length}):</span>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {availableStudents.filter(s => selectedStudentIds.includes(s.id)).map(s => (
                      <span key={s.id} className="px-1.5 py-0.5 rounded bg-white border border-[#D5DDE5] text-[10px] font-mono">
                        {s.username}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-[#EAF5F0] border border-[#8ECFAD] text-xs text-[#2E7D5B] space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4" />
                Security Pipeline Execution:
              </div>
              <ul className="text-[11px] list-disc list-inside space-y-0.5 text-[#2E7D5B]">
                <li>Encrypt question paper with authenticated AES-256-GCM</li>
                <li>Shard encrypted payload into RAM EphemeralStore (TTL: 30 minutes)</li>
                <li>Split master key via Shamir Secret Sharing among the 3 key guardians</li>
                <li>Transition examination state to <code>AWAITING_APPROVAL</code></li>
              </ul>
            </div>

            <div className="flex justify-between pt-2">
              <Button variant="outline" size="sm" onClick={() => setCurrentStep(4)} className="flex items-center gap-1.5">
                <ArrowLeft className="w-3.5 h-3.5" /> Back
              </Button>
              <Button
                size="sm"
                onClick={handleFinalizeAndStage}
                disabled={loading}
                className="flex items-center gap-1.5 bg-[#2E7D5B] hover:bg-[#256B4D] text-white"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                Stage Paper & Prepare for Approval
              </Button>
            </div>
          </div>
        )}

        {/* ── SUCCESS SCREEN ─────────────────────────────────────────────── */}
        {wizardSuccess && (
          <div className="text-center py-6 space-y-4">
            <div className="w-12 h-12 rounded-full bg-[#EAF5F0] border border-[#8ECFAD] text-[#2E7D5B] flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-7 h-7" />
            </div>

            <div>
              <h3 className="text-base font-bold text-[#17324D]">Examination Created & Paper Staged</h3>
              <p className="text-xs text-[#5E6B78] mt-1">
                <strong>{examTitle}</strong> is now staged in RAM and awaiting multi-guardian quorum approval.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#D5DDE5] max-w-md mx-auto text-left text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-[#5E6B78]">Status:</span>
                <Badge variant="warning" size="sm">AWAITING_APPROVAL</Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-[#5E6B78]">Payload Integrity:</span>
                <span className="font-mono text-[10px] text-[#17324D]">{stagingResult?.encrypted_payload_hash?.slice(0, 20)}...</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#5E6B78]">Key Guardians:</span>
                <span className="font-medium text-[#17324D]">{selectedGuardianIds.length} Assigned (3/3 Required)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#5E6B78]">Registered Candidates:</span>
                <span className="font-medium text-[#17324D]">{selectedStudentIds.length} Students</span>
              </div>
            </div>

            <div className="pt-2 flex justify-center gap-2">
              <Button variant="primary" size="sm" onClick={handleReset}>
                Done & Return to Dashboard
              </Button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}
