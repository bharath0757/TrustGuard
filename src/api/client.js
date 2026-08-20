/**
 * Centralized API HTTP Client for TrustGuard Frontend.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

// Token storage key
const TOKEN_KEY = 'trustguard_jwt_token';

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (token) => localStorage.setItem(TOKEN_KEY, token);
export const removeToken = () => localStorage.removeItem(TOKEN_KEY);

/**
 * Format backend error responses (strings, arrays of Pydantic validation errors, or objects)
 * into a clear human-readable error message.
 */
function extractErrorMessage(errorData, response) {
  if (!errorData) {
    return `HTTP ${response.status}: ${response.statusText || 'API request failed'}`;
  }

  // Case 1: detail is a simple string
  if (typeof errorData.detail === 'string') {
    return errorData.detail;
  }

  // Case 2: detail is a FastAPI / Pydantic validation error array
  if (Array.isArray(errorData.detail)) {
    const messages = errorData.detail.map((err) => {
      if (typeof err === 'string') return err;
      if (err && typeof err === 'object') {
        const field = Array.isArray(err.loc)
          ? err.loc.filter((locPart) => locPart !== 'body' && locPart !== 'query').join('.')
          : '';
        const msg = err.msg || JSON.stringify(err);
        return field ? `${field}: ${msg}` : msg;
      }
      return String(err);
    });
    return messages.filter(Boolean).join('; ') || 'Validation error';
  }

  // Case 3: detail is an object
  if (errorData.detail && typeof errorData.detail === 'object') {
    return JSON.stringify(errorData.detail);
  }

  // Case 4: generic message or error property
  if (errorData.message) {
    return errorData.message;
  }

  if (errorData.error) {
    return errorData.error;
  }

  return `HTTP ${response.status}: ${response.statusText || 'API request failed'}`;
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  const token = getToken();
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
  };

  try {
    const response = await fetch(url, config);
    if (!response.ok) {
      const errorData = await response.json().catch(async () => {
        const text = await response.text().catch(() => '');
        return { detail: text || response.statusText };
      });

      const message = extractErrorMessage(errorData, response);
      const error = new Error(message);
      error.status = response.status;
      error.statusText = response.statusText;
      error.data = errorData;
      throw error;
    }
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    return await response.text();
  } catch (err) {
    console.warn(`[API Client Error] ${endpoint} (status ${err.status || 'network'}):`, err.message);
    throw err;
  }
}

export const api = {
  // Auth
  register: (data) => request('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  login: (data) => request('/auth/login', { method: 'POST', body: JSON.stringify(data) }),
  getMe: () => request('/auth/me'),

  // Health
  getHealth: () => request('/health'),

  // Exams
  getExams: () => request('/exams/'),
  getExam: (id) => request(`/exams/${id}`),
  createExam: (data) => request('/exams/', { method: 'POST', body: JSON.stringify(data) }),
  assignGuardian: (id, data) => request(`/exams/${id}/guardians`, { method: 'POST', body: JSON.stringify(data) }),
  stagePayload: (id, data) => request(`/exams/${id}/stage-payload`, { method: 'POST', body: JSON.stringify(data) }),

  // Consensus
  submitApproval: (id, data) => request(`/consensus/${id}/approve`, { method: 'POST', body: JSON.stringify(data) }),
  getQuorumStatus: (id) => request(`/consensus/${id}/status`),

  // Ephemeral Distribution
  streamPayload: async (id) => {
    const url = `${API_BASE_URL}/distribution/${id}/stream`;
    const token = getToken();
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const errText = await res.text();
      const err = new Error(errText || 'Streaming failed');
      err.status = res.status;
      throw err;
    }
    return await res.text();
  },
  purgeEphemeral: (id) => request(`/distribution/${id}/purge`, { method: 'POST' }),

  // Audit
  getAuditEvents: (examId) => request(examId ? `/audit/events?exam_id=${examId}` : '/audit/events'),
  logAuditEvent: (data) => request('/audit/events', { method: 'POST', body: JSON.stringify(data) }),
};
