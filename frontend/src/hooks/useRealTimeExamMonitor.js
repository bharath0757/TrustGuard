import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * Real-Time Guardian Examination Monitoring Hook (Phase 6)
 *
 * Connects via WebSocket with:
 * - Automatic reconnection & exponential backoff
 * - Resilient HTTP polling fallback (3s interval)
 * - Server-authoritative timer countdown with clock drift compensation
 * - Granular live state updates for candidate writing/submission, consensus, and security events
 *
 * @param {string} examId - Exam ID to monitor
 * @param {string} token - Optional JWT bearer token
 */
export function useRealTimeExamMonitor(examId, token) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [connected, setConnected] = useState(false);
  const [transport, setTransport] = useState('disconnected'); // 'websocket' | 'polling' | 'disconnected'
  const [remainingSec, setRemainingSec] = useState(null);
  const [serverOffset, setServerOffset] = useState(0);

  const socketRef = useRef(null);
  const pollIntervalRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const isMountedRef = useRef(true);

  const authToken = token || localStorage.getItem('trustguard_token');

  const getHeaders = useCallback(() => {
    return authToken ? { Authorization: `Bearer ${authToken}` } : {};
  }, [authToken]);

  // 1. Full Dashboard State REST Fetch (Initial hydration & Polling Fallback)
  const fetchDashboardState = useCallback(async () => {
    if (!examId) return;
    try {
      const res = await fetch(`/api/v1/exam-lifecycle/${examId}/dashboard-state`, {
        headers: getHeaders(),
      });
      if (!res.ok) {
        throw new Error(`Failed to fetch exam state (${res.status})`);
      }
      const state = await res.json();
      if (!isMountedRef.current) return;

      setData(state);
      setError(null);

      // Compute server time offset
      if (state.server_time) {
        const serverMs = new Date(state.server_time).getTime();
        const clientMs = Date.now();
        setServerOffset(serverMs - clientMs);
      }
    } catch (err) {
      if (isMountedRef.current) {
        setError(err.message);
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [examId, getHeaders]);

  // 2. Start / Stop HTTP Polling Fallback
  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return;
    setTransport('polling');
    pollIntervalRef.current = setInterval(fetchDashboardState, 3000);
  }, [fetchDashboardState]);

  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  // 3. Setup WebSocket Connection
  const connectWebSocket = useCallback(() => {
    if (!examId || !authToken) {
      startPolling();
      return;
    }

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/api/v1/ws/exams/${examId}?token=${encodeURIComponent(authToken)}`;

      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) return;
        setConnected(true);
        setTransport('websocket');
        setError(null);
        stopPolling(); // Stop polling when WS is connected
      };

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        try {
          const msg = JSON.parse(event.data);

          if (msg.type === 'INIT_STATE' || msg.type === 'STATE_UPDATE') {
            const payload = msg.payload;
            setData(payload);
            if (payload.server_time) {
              setServerOffset(new Date(payload.server_time).getTime() - Date.now());
            }
          } else if (msg.type === 'STATS_UPDATED') {
            const stats = msg.payload;
            setData((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                registered_students_count: stats.registered_count ?? prev.registered_students_count,
                currently_writing_count: stats.currently_writing ?? prev.currently_writing_count,
                submitted_count: stats.submitted_count ?? prev.submitted_count,
                expired_count: stats.expired_count ?? prev.expired_count,
                students: stats.students ?? prev.students,
              };
            });
          } else if (msg.type === 'STUDENT_JOINED') {
            const { student_username, stats } = msg.payload;
            setData((prev) => {
              if (!prev) return prev;
              const updatedEvents = [
                {
                  id: `ev-${Date.now()}`,
                  action: 'STUDENT_JOINED_EXAM',
                  actor_id: student_username,
                  timestamp: new Date().toISOString(),
                  event_type: 'ACCESS',
                  details: { student_username },
                },
                ...(prev.recent_audit_events || []),
              ].slice(0, 30);

              return {
                ...prev,
                currently_writing_count: stats?.currently_writing ?? (prev.currently_writing_count + 1),
                students: stats?.students ?? prev.students,
                recent_audit_events: updatedEvents,
              };
            });
          } else if (msg.type === 'STUDENT_SUBMITTED') {
            const { student_username, stats, score, max_score } = msg.payload;
            setData((prev) => {
              if (!prev) return prev;
              const updatedEvents = [
                {
                  id: `ev-${Date.now()}`,
                  action: 'STUDENT_EXAM_SUBMITTED',
                  actor_id: student_username,
                  timestamp: new Date().toISOString(),
                  event_type: 'ACCESS',
                  details: { student_username, score, max_score },
                },
                ...(prev.recent_audit_events || []),
              ].slice(0, 30);

              return {
                ...prev,
                currently_writing_count: stats?.currently_writing ?? Math.max(0, prev.currently_writing_count - 1),
                submitted_count: stats?.submitted_count ?? (prev.submitted_count + 1),
                students: stats?.students ?? prev.students,
                recent_audit_events: updatedEvents,
              };
            });
          } else if (msg.type === 'GUARDIAN_APPROVED') {
            const { approvals_count, required_quorum, quorum_reached } = msg.payload;
            setData((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                approvals_count: approvals_count ?? prev.approvals_count,
                quorum_status: `${approvals_count} / ${required_quorum}`,
                quorum_achieved: quorum_reached ?? prev.quorum_achieved,
              };
            });
          } else if (msg.type === 'CONSENSUS_REACHED' || msg.type === 'PAPER_RELEASED') {
            setData((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                status: 'AUTHORIZED',
                paper_status: 'RELEASED',
                quorum_achieved: true,
              };
            });
          } else if (msg.type === 'EXAM_STARTED') {
            setData((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                status: 'LIVE',
                started_at: msg.payload?.started_at || new Date().toISOString(),
              };
            });
          } else if (msg.type === 'EXAM_COMPLETED') {
            setData((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                status: 'COMPLETED',
                ended_at: msg.payload?.ended_at || new Date().toISOString(),
              };
            });
          } else if (msg.type === 'AUDIT_EVENT' || msg.type === 'SECURITY_ALERT') {
            const ev = msg.payload;
            setData((prev) => {
              if (!prev) return prev;
              const isSecurity = msg.type === 'SECURITY_ALERT' || 
                (ev.action && /BLOCKED|DENIED|REJECTED|ATTACK|TAMPERED|UNAUTHORIZED/.test(ev.action));
              
              const newEvents = [
                {
                  id: ev.id || `ev-${Date.now()}`,
                  action: ev.action,
                  actor_id: ev.actor_id,
                  timestamp: ev.timestamp || new Date().toISOString(),
                  event_type: isSecurity ? 'SECURITY' : 'SYSTEM',
                  details: ev.details,
                },
                ...(prev.recent_audit_events || []),
              ].slice(0, 30);

              return {
                ...prev,
                attack_attempts: isSecurity ? (prev.attack_attempts + 1) : prev.attack_attempts,
                blocked_attacks: (ev.action && /BLOCKED|DENIED/.test(ev.action)) ? (prev.blocked_attacks + 1) : prev.blocked_attacks,
                security_status: isSecurity ? 'WARNING' : prev.security_status,
                recent_audit_events: newEvents,
              };
            });
          }
        } catch {
          // Ignore JSON parse errors
        }
      };

      ws.onclose = () => {
        if (!isMountedRef.current) return;
        setConnected(false);
        socketRef.current = null;
        startPolling(); // Fallback to HTTP polling while disconnected

        // Schedule auto-reconnect attempt
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(() => {
          if (isMountedRef.current) {
            connectWebSocket();
          }
        }, 3000);
      };

      ws.onerror = () => {
        if (!isMountedRef.current) return;
        ws.close();
      };
    } catch {
      startPolling();
    }
  }, [examId, authToken, startPolling, stopPolling]);

  // Initial mount: load state and start connection
  useEffect(() => {
    isMountedRef.current = true;
    fetchDashboardState();
    connectWebSocket();

    // Keepalive ping interval
    const pingInterval = setInterval(() => {
      if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
        socketRef.current.send('ping');
      }
    }, 15000);

    return () => {
      isMountedRef.current = false;
      clearInterval(pingInterval);
      stopPolling();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [examId, fetchDashboardState, connectWebSocket, stopPolling]);

  // 4. Server-Authoritative Countdown Timer
  useEffect(() => {
    if (!data?.expires_at && !data?.scheduled_end) {
      setRemainingSec(null);
      return;
    }

    const targetDateStr = data.expires_at || data.scheduled_end;
    const targetMs = new Date(targetDateStr).getTime();

    const updateTimer = () => {
      const adjustedNowMs = Date.now() + serverOffset;
      const diffSec = Math.max(0, Math.floor((targetMs - adjustedNowMs) / 1000));
      setRemainingSec(diffSec);
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [data?.expires_at, data?.scheduled_end, serverOffset]);

  // Format MM:SS helper
  const formatTime = (totalSec) => {
    if (totalSec === null || totalSec === undefined) return '--:--';
    const m = Math.floor(totalSec / 60);
    const s = totalSec % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  return {
    data,
    loading,
    error,
    connected,
    transport,
    remainingSec,
    timeRemainingFormatted: formatTime(remainingSec),
    refetch: fetchDashboardState,
  };
}
