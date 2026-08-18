import { useState, useCallback } from 'react';

const API_BASE = '/api/v1';

/**
 * Hook for Multi-Guardian Consensus & Quorum Authorization operations.
 */
export function useConsensus() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const getHeaders = useCallback(() => {
    const token = localStorage.getItem('trustguard_token');
    return {
      'Content-Type': 'application/json',
      Authorization: token ? `Bearer ${token}` : '',
    };
  }, []);

  const handleError = useCallback((err) => {
    const msg = err?.detail || err?.message || 'An error occurred during consensus operation';
    setError(msg);
    return null;
  }, []);

  // ── Fetch Quorum Status for an Exam ────────────────────────────────
  const getQuorumStatus = useCallback(async (examId) => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/consensus/${examId}/status`, {
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    }
  }, [getHeaders, handleError]);

  // ── Submit Guardian Authorization Vote ──────────────────────────────
  const submitApproval = useCallback(async (examId, shareToken = null, comments = null) => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const payload = {};
      if (shareToken) payload.share_token = shareToken;
      if (comments) payload.comments = comments;

      const res = await fetch(`${API_BASE}/consensus/${examId}/approve`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw await res.json();
      const data = await res.json();
      setSuccessMsg(data.message || 'Authorization signature submitted successfully');
      return data;
    } catch (err) {
      return handleError(err);
    } finally {
      setLoading(false);
    }
  }, [getHeaders, handleError]);

  // ── List Pending Consensus Exams ────────────────────────────────────
  const listPendingExams = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/consensus/pending`, {
        headers: getHeaders(),
      });
      if (!res.ok) throw await res.json();
      return await res.json();
    } catch (err) {
      return handleError(err);
    }
  }, [getHeaders, handleError]);

  // ── Get Audit Events for Exam ───────────────────────────────────────
  const getExamAuditEvents = useCallback(async (examId) => {
    try {
      const res = await fetch(`${API_BASE}/audit/events?exam_id=${encodeURIComponent(examId)}`, {
        headers: getHeaders(),
      });
      if (!res.ok) return [];
      return await res.json();
    } catch (err) {
      return [];
    }
  }, [getHeaders]);

  return {
    loading,
    error,
    successMsg,
    setError,
    setSuccessMsg,
    getQuorumStatus,
    submitApproval,
    listPendingExams,
    getExamAuditEvents,
  };
}
