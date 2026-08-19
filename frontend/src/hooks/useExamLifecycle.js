import { useState, useCallback } from 'react';

const API_BASE = '/api/v1';

/**
 * Centralized hook for exam lifecycle API interactions.
 * Handles upload, exam creation, start/end, security status, and report.
 */
export function useExamLifecycle() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Helper: get auth headers from localStorage (compatible with AuthContext)
  const getHeaders = useCallback(() => {
    const token = localStorage.getItem('trustguard_token');
    return {
      Authorization: token ? `Bearer ${token}` : '',
    };
  }, []);

  const handleError = useCallback((err) => {
    const msg = err?.detail || err?.message || 'An error occurred';
    setError(msg);
    return null;
  }, []);

  // ── Upload Paper ────────────────────────────────────────────────────
  const uploadPaper = useCallback(async (file, paperName, description) => {
    setLoading(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('paper_name', paperName);
      if (description) formData.append('description', description);

      const res = await fetch(`${API_BASE}/papers/upload`, {
        method: 'POST',
        headers: { Authorization: getHeaders().Authorization },
        body: formData,
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── List Papers ─────────────────────────────────────────────────────
  const listPapers = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/papers/`, {
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      handleError(err);
      return [];
    }
  }, [getHeaders, handleError]);

  // ── Create Exam ─────────────────────────────────────────────────────
  const createExam = useCallback(async (examData) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exams/`, {
        method: 'POST',
        headers: { ...getHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(examData),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── List Exams ──────────────────────────────────────────────────────
  const listExams = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exams/`, {
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      handleError(err);
      return [];
    }
  }, [getHeaders, handleError]);

  // ── Start Exam ──────────────────────────────────────────────────────
  const startExam = useCallback(async (examId) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exam-lifecycle/${examId}/start`, {
        method: 'POST',
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── End Exam ────────────────────────────────────────────────────────
  const endExam = useCallback(async (examId) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exam-lifecycle/${examId}/end`, {
        method: 'POST',
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── Security Status ─────────────────────────────────────────────────
  const getSecurityStatus = useCallback(async (examId) => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exam-lifecycle/${examId}/security`, {
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      handleError(err);
      return null;
    }
  }, [getHeaders, handleError]);

  // ── Events (polling) ────────────────────────────────────────────────
  const getEvents = useCallback(async (examId, since = null) => {
    setError(null);
    try {
      let url = `${API_BASE}/exam-lifecycle/${examId}/events`;
      if (since) url += `?since=${encodeURIComponent(since)}`;
      const res = await fetch(url, { headers: getHeaders() });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      handleError(err);
      return [];
    }
  }, [getHeaders, handleError]);

  // ── Report ──────────────────────────────────────────────────────────
  const getReport = useCallback(async (examId) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exam-lifecycle/${examId}/report`, {
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── Assign Guardian ────────────────────────────────────────────────
  const assignGuardian = useCallback(async (examId, guardianUserId, fingerprint = 'RSA_4096_FP') => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exams/${examId}/guardians`, {
        method: 'POST',
        headers: { ...getHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          guardian_user_id: guardianUserId,
          public_key_fingerprint: fingerprint,
        }),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── Register Students ───────────────────────────────────────────────
  const registerStudents = useCallback(async (examId, studentUserIds) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exams/${examId}/students`, {
        method: 'POST',
        headers: { ...getHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          student_user_ids: studentUserIds,
        }),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── Stage Paper ─────────────────────────────────────────────────────
  const stagePaper = useCallback(async (examId, paperId = null, ttlSeconds = 1800) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exams/${examId}/stage-paper`, {
        method: 'POST',
        headers: { ...getHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          paper_id: paperId,
          ttl_seconds: ttlSeconds,
        }),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── Get Users (Guardians / Students) ────────────────────────────────
  const getUsers = useCallback(async (role = null) => {
    setError(null);
    try {
      let url = `${API_BASE}/users/`;
      if (role) url += `?role=${encodeURIComponent(role)}`;
      const res = await fetch(url, { headers: getHeaders() });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      handleError(err);
      return [];
    }
  }, [getHeaders, handleError]);

  // ── Get Exam by ID ──────────────────────────────────────────────────
  const getExam = useCallback(async (examId) => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/exams/${examId}`, { headers: getHeaders() });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      handleError(err);
      return null;
    }
  }, [getHeaders, handleError]);

  return {
    loading,
    error,
    setError,
    uploadPaper,
    listPapers,
    createExam,
    listExams,
    getExam,
    assignGuardian,
    registerStudents,
    stagePaper,
    getUsers,
    startExam,
    endExam,
    getSecurityStatus,
    getEvents,
    getReport,
    runSimulation,
  };
}
