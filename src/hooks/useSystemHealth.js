import { useState, useEffect, useCallback } from 'react';

const HEALTH_URL = '/api/v1/health';

/**
 * useSystemHealth — polls the backend /health endpoint.
 * Returns connection status, overall health, and database status.
 */
export function useSystemHealth(pollInterval = 30000) {
  const [isBackendConnected, setIsBackendConnected] = useState(false);
  const [status, setStatus] = useState('unknown');
  const [database, setDatabase] = useState('unknown');

  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch(HEALTH_URL);
      if (res.ok) {
        const data = await res.json();
        setIsBackendConnected(true);
        setStatus(data.status || 'healthy');
        setDatabase(data.database || 'connected');
      } else {
        setIsBackendConnected(false);
        setStatus('unhealthy');
        setDatabase('disconnected');
      }
    } catch {
      setIsBackendConnected(false);
      setStatus('unreachable');
      setDatabase('disconnected');
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, pollInterval);
    return () => clearInterval(interval);
  }, [checkHealth, pollInterval]);

  return { isBackendConnected, status, database, refresh: checkHealth };
}
