import { useState, useEffect, useCallback } from 'react';

/**
 * Hook to monitor live TrustGuard backend & database health status.
 * Automatically fails over to standalone demo mode if backend is offline.
 */
export function useSystemHealth(pollIntervalMs = 30000) {
  const [healthState, setHealthState] = useState({
    status: 'checking', // 'checking' | 'healthy' | 'degraded' | 'offline'
    service: 'TrustGuard Backend API',
    version: '0.1.0',
    database: 'checking',
    ephemeralStore: 'checking',
    lastChecked: null,
    isBackendConnected: false,
  });

  const checkHealth = useCallback(async () => {
    try {
      // Try relative URL first (works with Vite proxy or same-origin), fallback to default port 8000
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      let response;
      try {
        response = await fetch('/health', { signal: controller.signal });
      } catch {
        response = await fetch('http://localhost:8000/health', { signal: controller.signal });
      } finally {
        clearTimeout(timeoutId);
      }

      if (response && response.ok) {
        const data = await response.json();
        setHealthState({
          status: data.status || 'healthy',
          service: data.service || 'TrustGuard Backend API',
          version: data.version || '0.1.0',
          database: data.database || 'connected',
          ephemeralStore: data.ephemeral_store || 'ready',
          lastChecked: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          isBackendConnected: true,
        });
      } else {
        throw new Error('Health check returned non-200');
      }
    } catch {
      setHealthState((prev) => ({
        ...prev,
        status: 'offline',
        database: 'standalone',
        ephemeralStore: 'in-memory',
        lastChecked: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        isBackendConnected: false,
      }));
    }
  }, []);

  useEffect(() => {
    checkHealth();
    if (pollIntervalMs > 0) {
      const interval = setInterval(checkHealth, pollIntervalMs);
      return () => clearInterval(interval);
    }
  }, [checkHealth, pollIntervalMs]);

  return {
    ...healthState,
    checkHealth,
  };
}
