import { useState, useCallback } from 'react';
import { api } from '../api/client';

/**
 * useConsensus — wraps backend consensus API calls.
 * Used by ApprovalsPage for quorum status, approval submission, and audit events.
 */
export function useConsensus() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const getQuorumStatus = useCallback(async (examId) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getQuorumStatus(examId);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to fetch quorum status');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const submitApproval = useCallback(async (examId, approvalData) => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const data = await api.submitApproval(examId, approvalData);
      setSuccessMsg('Approval submitted successfully');
      return data;
    } catch (err) {
      setError(err.message || 'Failed to submit approval');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const listPendingExams = useCallback(async () => {
    setLoading(true);
    try {
      const exams = await api.getExams();
      return Array.isArray(exams) ? exams.filter(e =>
        ['AWAITING_APPROVAL', 'CONSENSUS_PENDING', 'EPHEMERAL_PAYLOAD_STAGED'].includes(e.status)
      ) : [];
    } catch (err) {
      setError(err.message || 'Failed to list pending exams');
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  const getExamAuditEvents = useCallback(async (examId) => {
    try {
      const events = await api.getAuditEvents(examId);
      return Array.isArray(events) ? events : [];
    } catch {
      return [];
    }
  }, []);

  return {
    loading,
    error,
    successMsg,
    getQuorumStatus,
    submitApproval,
    listPendingExams,
    getExamAuditEvents,
  };
}
