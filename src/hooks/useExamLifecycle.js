import { useState, useCallback } from 'react';
import { api } from '../api/client';

/**
 * useExamLifecycle — wraps backend exam lifecycle API calls.
 * Used by ApprovalsPage and other pages for exam CRUD operations.
 */
export function useExamLifecycle() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const listExams = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const exams = await api.getExams();
      return Array.isArray(exams) ? exams : [];
    } catch (err) {
      setError(err.message || 'Failed to list exams');
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  const getExam = useCallback(async (id) => {
    setLoading(true);
    setError(null);
    try {
      return await api.getExam(id);
    } catch (err) {
      setError(err.message || 'Failed to fetch exam');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const createExam = useCallback(async (data) => {
    setLoading(true);
    setError(null);
    try {
      return await api.createExam(data);
    } catch (err) {
      setError(err.message || 'Failed to create exam');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const stagePayload = useCallback(async (examId, data) => {
    setLoading(true);
    setError(null);
    try {
      return await api.stagePayload(examId, data);
    } catch (err) {
      setError(err.message || 'Failed to stage payload');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { loading, error, listExams, getExam, createExam, stagePayload };
}
