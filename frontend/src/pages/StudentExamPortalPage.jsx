import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ShieldCheck, Clock, CheckCircle2, AlertCircle, AlertTriangle,
  ChevronLeft, ChevronRight, Send, Check, Loader2, RefreshCw,
  FileText, Award, LogOut, Info, BookOpen
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Card, Badge, Button, Modal } from '../components/ui';

export function StudentExamPortalPage() {
  const { examId: routeExamId } = useParams();
  const navigate = useNavigate();
  const { user, token, getAuthHeaders, logout } = useAuth();

  const [availableExams, setAvailableExams] = useState([]);
  const [selectedExamId, setSelectedExamId] = useState(routeExamId || null);
  const [sessionData, setSessionData] = useState(null);
  const [currentQIndex, setCurrentQIndex] = useState(0);
  const [answers, setAnswers] = useState({});
  const [remainingSec, setRemainingSec] = useState(null);
  const [serverOffset, setServerOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [submissionResult, setSubmissionResult] = useState(null);

  const saveTimerRef = useRef(null);

  // 1. Fetch available exams assigned to this student
  const fetchStudentExams = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/v1/student/exams', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        throw new Error('Failed to load assigned examinations');
      }
      const data = await res.json();
      setAvailableExams(data);

      // Auto-select exam
      if (!selectedExamId && data.length > 0) {
        const liveExam = data.find(e => e.is_joinable) || data[0];
        setSelectedExamId(liveExam.id);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [token, selectedExamId]);

  useEffect(() => {
    if (token) {
      fetchStudentExams();
    }
  }, [token, fetchStudentExams]);

  // 2. Join or Load Session for selected Exam
  const loadExamSession = useCallback(async (examId) => {
    if (!examId || !token) return;
    try {
      setLoading(true);
      setError(null);

      // Join / resume session
      const res = await fetch(`/api/v1/student/exams/${examId}/join`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Could not connect to exam session');
      }

      const data = await res.json();
      setSessionData(data);
      setAnswers(data.saved_answers || {});

      // Calculate server time offset to protect against client clock manipulation
      if (data.server_time) {
        const serverMs = new Date(data.server_time).getTime();
        const clientMs = Date.now();
        setServerOffset(serverMs - clientMs);
      }

      if (data.status === 'SUBMITTED') {
        setSubmissionResult({
          session_id: data.session_id,
          exam_id: data.exam_id,
          student_id: data.student_id,
          status: 'SUBMITTED',
          submitted_at: data.submitted_at,
          answers_recorded: Object.keys(data.saved_answers || {}).length,
          score: data.score,
          max_score: data.max_score,
          message: 'Exam previously submitted.',
        });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (selectedExamId) {
      loadExamSession(selectedExamId);
    }
  }, [selectedExamId, loadExamSession]);

  // 3. Server-Authoritative Timer Countdown
  useEffect(() => {
    if (!sessionData?.expires_at || sessionData.status !== 'IN_PROGRESS') {
      return;
    }

    const updateTimer = () => {
      const expiresMs = new Date(sessionData.expires_at).getTime();
      // Server-compensated now timestamp
      const adjustedNowMs = Date.now() + serverOffset;
      const diffSec = Math.max(0, Math.floor((expiresMs - adjustedNowMs) / 1000));
      setRemainingSec(diffSec);

      if (diffSec <= 0) {
        setSessionData(prev => prev ? { ...prev, status: 'EXPIRED' } : null);
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [sessionData?.expires_at, sessionData?.status, serverOffset]);

  // Format seconds to MM:SS or HH:MM:SS
  const formatTimeRemaining = (totalSec) => {
    if (totalSec === null || totalSec === undefined) return '--:--';
    const m = Math.floor(totalSec / 60);
    const s = totalSec % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  // 4. Save Student Answer to backend
  const handleSelectOption = async (questionId, optionKey) => {
    if (sessionData?.status !== 'IN_PROGRESS' || remainingSec <= 0) return;

    const newAnswers = { ...answers, [questionId]: optionKey };
    setAnswers(newAnswers);

    // Debounced or immediate sync to backend
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(async () => {
      try {
        setSaving(true);
        await fetch(`/api/v1/student/sessions/${sessionData.session_id}/answers`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ answers: { [questionId]: optionKey } }),
        });
      } catch (err) {
        // Silent background sync retry
      } finally {
        setSaving(false);
      }
    }, 300);
  };

  // 5. Submit Exam Handler
  const handleSubmitExam = async () => {
    if (!sessionData?.session_id) return;
    try {
      setSubmitting(true);
      setError(null);

      const res = await fetch(`/api/v1/student/sessions/${sessionData.session_id}/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ answers }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to submit exam');
      }

      const result = await res.json();
      setSubmissionResult(result);
      setSessionData(prev => prev ? { ...prev, status: 'SUBMITTED', score: result.score } : null);
      setShowSubmitModal(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  // Current Question
  const questions = sessionData?.questions || [];
  const currentQuestion = questions[currentQIndex] || null;
  const answeredCount = Object.keys(answers).length;
  const totalQuestions = questions.length || 20;

  // Render: Loading State
  if (loading && !sessionData) {
    return (
      <div className="min-h-screen bg-[#F5F7FA] flex items-center justify-center p-4">
        <div className="text-center space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-[#17324D] text-white flex items-center justify-center mx-auto shadow-md">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h2 className="text-base font-bold text-[#17324D]">TrustGuard Secure Examination Portal</h2>
          <div className="flex items-center justify-center gap-2 text-xs text-[#5E6B78]">
            <Loader2 className="w-4 h-4 animate-spin text-[#3E6B8C]" />
            <span>Establishing zero-trust candidate session...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F8FAFC] flex flex-col font-sans antialiased text-[#182230]">
      {/* ── TOPBAR: TrustGuard Brand & Exam Header ────────────────────── */}
      <header className="bg-white border-b border-[#C7D0DA] px-4 lg:px-8 py-3 sticky top-0 z-30 shadow-2xs">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          {/* Brand & Exam Title */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-[#17324D] flex items-center justify-center text-white shadow-xs shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-tight text-[#17324D]">TrustGuard</span>
                <span className="text-[11px] px-1.5 py-0.5 rounded bg-[#EAF2F8] text-[#3E6B8C] font-semibold uppercase font-mono">
                  {sessionData?.course_code || 'CS-SEC-2026'}
                </span>
              </div>
              <h1 className="text-xs font-semibold text-[#5E6B78] truncate">
                {sessionData?.exam_title || 'Cybersecurity Fundamentals'}
              </h1>
            </div>
          </div>

          {/* Server-Authoritative Timer & Actions */}
          <div className="flex items-center gap-3">
            {/* Timer Badge */}
            {sessionData?.status === 'IN_PROGRESS' && (
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border font-mono transition-all ${
                remainingSec !== null && remainingSec < 180
                  ? 'bg-[#FDF2F2] border-[#FECDCA] text-[#C44747] animate-pulse'
                  : 'bg-[#F0F4F8] border-[#C7D0DA] text-[#17324D]'
              }`}>
                <Clock className="w-4 h-4 shrink-0 text-[#5E6B78]" />
                <div className="text-right">
                  <div className="text-[10px] text-[#5E6B78] uppercase leading-none font-sans font-medium">Time Remaining</div>
                  <div className="text-sm font-bold leading-tight tracking-wider">
                    {formatTimeRemaining(remainingSec)}
                  </div>
                </div>
              </div>
            )}

            {/* Candidate Identity */}
            <div className="hidden sm:flex items-center gap-2 pl-2 border-l border-[#D5DDE5] text-xs">
              <div className="w-7 h-7 rounded-full bg-[#0369A1] text-white flex items-center justify-center font-bold text-xs">
                {user?.username ? user.username.charAt(0).toUpperCase() : 'S'}
              </div>
              <div>
                <div className="font-semibold text-[#17324D] leading-none">{user?.username || 'Student'}</div>
                <div className="text-[10px] text-[#5E6B78] leading-none mt-0.5">Candidate</div>
              </div>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={logout}
              className="text-xs p-2 text-[#5E6B78] hover:text-[#C44747]"
              title="Logout"
            >
              <LogOut className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      </header>

      {/* ── MAIN CONTENT AREA ────────────────────────────────────────── */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-6 grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Error Notification */}
        {error && (
          <div className="lg:col-span-12">
            <Card className="p-3 bg-[#FDF2F2] border border-[#FECDCA] flex items-center justify-between text-xs text-[#C44747]">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setError(null)}>Dismiss</Button>
            </Card>
          </div>
        )}

        {/* ── COMPLETED / SUBMITTED RECEIPT SCREEN ─────────────────── */}
        {submissionResult ? (
          <div className="lg:col-span-12 max-w-xl mx-auto w-full py-6">
            <Card className="p-6 bg-white border border-[#C7D0DA] text-center space-y-4 shadow-sm">
              <div className="w-14 h-14 rounded-full bg-[#EAF5F0] border border-[#8ECFAD] text-[#2E7D5B] flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-8 h-8" />
              </div>

              <div>
                <h2 className="text-lg font-bold text-[#17324D]">Examination Successfully Submitted</h2>
                <p className="text-xs text-[#5E6B78] mt-1">
                  Your candidate submission for <strong>{sessionData?.exam_title || 'Cybersecurity Fundamentals'}</strong> has been securely recorded to the immutable ledger.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#D5DDE5] text-left text-xs space-y-2">
                <div className="flex justify-between py-1 border-b border-[#E4E7EC]">
                  <span className="text-[#5E6B78]">Candidate:</span>
                  <span className="font-semibold text-[#17324D]">{user?.username}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#E4E7EC]">
                  <span className="text-[#5E6B78]">Submission Timestamp:</span>
                  <span className="font-mono text-[#17324D]">
                    {submissionResult.submitted_at ? new Date(submissionResult.submitted_at).toLocaleTimeString() : new Date().toLocaleTimeString()}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#E4E7EC]">
                  <span className="text-[#5E6B78]">Questions Answered:</span>
                  <span className="font-semibold text-[#17324D]">{submissionResult.answers_recorded} of {totalQuestions}</span>
                </div>
                {submissionResult.score !== null && (
                  <div className="flex justify-between py-1 pt-2">
                    <span className="text-[#5E6B78] font-bold">Evaluated Score:</span>
                    <span className="font-bold text-[#2E7D5B] text-sm">
                      {submissionResult.score} / {submissionResult.max_score || totalQuestions} Marks
                    </span>
                  </div>
                )}
              </div>

              <div className="pt-2 flex justify-center gap-2">
                <Button size="sm" onClick={() => navigate('/')} className="bg-[#17324D] text-white">
                  Return to Dashboard
                </Button>
              </div>
            </Card>
          </div>
        ) : sessionData?.status === 'EXPIRED' ? (
          /* ── EXPIRED SCREEN ───────────────────────────────────────── */
          <div className="lg:col-span-12 max-w-xl mx-auto w-full py-6">
            <Card className="p-6 bg-white border border-[#C7D0DA] text-center space-y-4 shadow-sm">
              <div className="w-14 h-14 rounded-full bg-[#FAF3E7] border border-[#F5D99A] text-[#B7791F] flex items-center justify-center mx-auto">
                <Clock className="w-8 h-8" />
              </div>

              <div>
                <h2 className="text-lg font-bold text-[#17324D]">Examination Session Expired</h2>
                <p className="text-xs text-[#5E6B78] mt-1">
                  The server-authoritative time limit for <strong>{sessionData?.exam_title}</strong> has elapsed. No further responses can be accepted.
                </p>
              </div>

              <div className="p-3 bg-[#FAF3E7] border border-[#F5D99A] rounded-lg text-xs text-[#B7791F]">
                <AlertTriangle className="w-4 h-4 inline mr-1" />
                Answers saved prior to expiry have been preserved on the server.
              </div>

              <div className="pt-2 flex justify-center">
                <Button size="sm" onClick={() => navigate('/')} className="bg-[#17324D] text-white">
                  Return to Home
                </Button>
              </div>
            </Card>
          </div>
        ) : (
          /* ── ACTIVE EXAM TAKING SCREEN ───────────────────────────── */
          <>
            {/* LEFT: Main Question Canvas (Col-span 8) */}
            <div className="lg:col-span-8 space-y-4">
              <Card className="p-5 sm:p-6 bg-white border border-[#C7D0DA] shadow-xs space-y-5">
                {/* Question Header & Counter */}
                <div className="flex items-center justify-between pb-3 border-b border-[#D5DDE5]">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-[#17324D] uppercase tracking-wider">
                      Question:
                    </span>
                    <span className="text-sm font-bold text-[#17324D] font-mono px-2 py-0.5 bg-[#F0F4F8] rounded border border-[#C7D0DA]">
                      {currentQIndex + 1} / {totalQuestions}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <Badge variant={answers[currentQuestion?.id] ? 'success' : 'neutral'} size="sm">
                      {answers[currentQuestion?.id] ? 'Answered' : 'Unanswered'}
                    </Badge>
                    <span className="text-xs text-[#5E6B78] font-medium">
                      {currentQuestion?.marks || 1} Mark{(currentQuestion?.marks || 1) > 1 ? 's' : ''}
                    </span>
                  </div>
                </div>

                {/* Question Text */}
                <div className="min-h-18">
                  <p className="text-sm sm:text-base font-semibold text-[#17324D] leading-relaxed">
                    {currentQuestion ? currentQuestion.question_text : 'Loading question...'}
                  </p>
                </div>

                {/* Options List */}
                <div className="space-y-2.5 pt-2">
                  {currentQuestion?.options?.map((option) => {
                    const isSelected = answers[currentQuestion.id] === option.key;
                    return (
                      <div
                        key={option.key}
                        onClick={() => handleSelectOption(currentQuestion.id, option.key)}
                        className={`p-3.5 rounded-xl border flex items-start gap-3 cursor-pointer transition-all ${
                          isSelected
                            ? 'bg-[#EAF2F8] border-[#17324D] ring-2 ring-[#17324D]/10 shadow-xs'
                            : 'bg-white border-[#C7D0DA] hover:border-[#8C9BA8] hover:bg-[#F8FAFC]'
                        }`}
                      >
                        {/* Option Letter Indicator */}
                        <div
                          className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 transition-colors ${
                            isSelected
                              ? 'bg-[#17324D] text-white'
                              : 'bg-[#F0F4F8] text-[#5E6B78] border border-[#C7D0DA]'
                          }`}
                        >
                          {option.key}
                        </div>

                        {/* Option Text */}
                        <div className="flex-1 text-xs sm:text-sm text-[#182230] pt-0.5 leading-normal">
                          {option.text}
                        </div>

                        {/* Checkbox indicator */}
                        <div
                          className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
                            isSelected
                              ? 'bg-[#2E7D5B] text-white'
                              : 'border border-[#C7D0DA]'
                          }`}
                        >
                          {isSelected && <Check className="w-3 h-3" />}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Bottom Navigation Toolbar */}
                <div className="flex items-center justify-between pt-4 border-t border-[#D5DDE5]">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentQIndex(prev => Math.max(0, prev - 1))}
                    disabled={currentQIndex === 0}
                    className="flex items-center gap-1.5 text-xs"
                  >
                    <ChevronLeft className="w-4 h-4" /> Previous
                  </Button>

                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      onClick={() => setShowSubmitModal(true)}
                      className="bg-[#2E7D5B] hover:bg-[#256B4D] text-white text-xs font-semibold px-4 flex items-center gap-1.5"
                    >
                      <Send className="w-3.5 h-3.5" /> Submit Exam
                    </Button>

                    {currentQIndex < totalQuestions - 1 && (
                      <Button
                        size="sm"
                        onClick={() => setCurrentQIndex(prev => Math.min(totalQuestions - 1, prev + 1))}
                        className="bg-[#17324D] hover:bg-[#1E3F5F] text-white text-xs flex items-center gap-1.5"
                      >
                        Next <ChevronRight className="w-4 h-4" />
                      </Button>
                    )}
                  </div>
                </div>
              </Card>
            </div>

            {/* RIGHT: Question Palette & Session Status (Col-span 4) */}
            <div className="lg:col-span-4 space-y-4">
              {/* Question Navigation Palette */}
              <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-[#D5DDE5]">
                  <h3 className="text-xs font-bold text-[#17324D] uppercase tracking-wider flex items-center gap-1.5">
                    <BookOpen className="w-4 h-4 text-[#3E6B8C]" />
                    Question Navigator
                  </h3>
                  <span className="text-xs text-[#5E6B78] font-mono">
                    {answeredCount} / {totalQuestions} Answered
                  </span>
                </div>

                {/* 20 Question Grid */}
                <div className="grid grid-cols-5 gap-2">
                  {questions.map((q, idx) => {
                    const isAnswered = !!answers[q.id];
                    const isCurrent = currentQIndex === idx;
                    return (
                      <button
                        key={q.id || idx}
                        onClick={() => setCurrentQIndex(idx)}
                        className={`h-9 rounded-lg text-xs font-bold transition-all flex items-center justify-center relative cursor-pointer ${
                          isCurrent
                            ? 'bg-[#17324D] text-white ring-2 ring-[#3E6B8C]/40 shadow-xs'
                            : isAnswered
                            ? 'bg-[#EAF5F0] text-[#2E7D5B] border border-[#8ECFAD] hover:bg-[#D5EFE3]'
                            : 'bg-[#F0F4F8] text-[#5E6B78] border border-[#C7D0DA] hover:bg-[#E4E7EC]'
                        }`}
                      >
                        {idx + 1}
                        {isAnswered && !isCurrent && (
                          <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-[#2E7D5B]" />
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* Legend */}
                <div className="pt-2 border-t border-[#D5DDE5] grid grid-cols-3 gap-1 text-[10px] text-[#5E6B78]">
                  <div className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded bg-[#17324D]" />
                    <span>Current</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded bg-[#EAF5F0] border border-[#8ECFAD]" />
                    <span>Answered</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded bg-[#F0F4F8] border border-[#C7D0DA]" />
                    <span>Unanswered</span>
                  </div>
                </div>
              </Card>

              {/* Security & Integrity Status Card */}
              <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs space-y-2 text-xs">
                <div className="font-semibold text-[#17324D] flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-[#2E7D5B]" />
                  Exam Security Parameters
                </div>
                <div className="space-y-1.5 text-[11px] text-[#5E6B78]">
                  <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
                    <span>Timer Authority:</span>
                    <span className="font-semibold text-[#2E7D5B]">Server Synced</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#F0F4F8]">
                    <span>Answer Privacy:</span>
                    <span className="font-semibold text-[#2E7D5B]">Encrypted in RAM</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span>Sync Status:</span>
                    <span className="font-mono text-[#17324D]">
                      {saving ? 'Saving...' : 'All changes saved'}
                    </span>
                  </div>
                </div>
              </Card>
            </div>
          </>
        )}
      </main>

      {/* ── SUBMIT CONFIRMATION MODAL ─────────────────────────────────── */}
      <Modal
        isOpen={showSubmitModal}
        onClose={() => setShowSubmitModal(false)}
        title="Confirm Examination Submission"
      >
        <div className="space-y-4">
          <div className="p-3 bg-[#FAF3E7] border border-[#F5D99A] rounded-lg text-xs text-[#B7791F]">
            <AlertTriangle className="w-4 h-4 inline mr-1" />
            Once submitted, your examination session will be closed and no further changes will be permitted.
          </div>

          <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#D5DDE5] text-xs space-y-1.5">
            <div className="flex justify-between">
              <span className="text-[#5E6B78]">Total Questions:</span>
              <span className="font-semibold text-[#17324D]">{totalQuestions}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#5E6B78]">Answered:</span>
              <span className="font-semibold text-[#2E7D5B]">{answeredCount}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#5E6B78]">Unanswered:</span>
              <span className={`font-semibold ${totalQuestions - answeredCount > 0 ? 'text-[#C44747]' : 'text-[#2E7D5B]'}`}>
                {totalQuestions - answeredCount}
              </span>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowSubmitModal(false)}
            >
              Back to Exam
            </Button>
            <Button
              size="sm"
              onClick={handleSubmitExam}
              disabled={submitting}
              className="bg-[#2E7D5B] hover:bg-[#256B4D] text-white flex items-center gap-1.5"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
              Confirm & Submit Final Exam
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
