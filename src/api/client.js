/**
 * Centralized API HTTP Client for TrustGuard Frontend.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

// Token storage key
const TOKEN_KEY = 'trustguard_jwt_token';

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (token) => localStorage.setItem(TOKEN_KEY, token);
export const removeToken = () => localStorage.removeItem(TOKEN_KEY);

async function request(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = { ...options.headers };

  // Set Content-Type only if not FormData
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

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
      const errorData = await response.json().catch(() => ({ detail: response.statusText }));
      const error = new Error(errorData.detail || 'API request failed');
      error.status = response.status;
      error.data = errorData;
      throw error;
    }
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    return await response.text();
  } catch (err) {
    console.warn(`[API Client Error] ${endpoint}:`, err.message);
    throw err;
  }
}

export const api = {
  // Auth
  register: (data) => request('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  login: (data) => request('/auth/login', { method: 'POST', body: JSON.stringify(data) }),
  getMe: () => request('/auth/me'),
  seedUsers: () => request('/users/seed', { method: 'POST' }),

  // Question Papers
  uploadPaper: (formData) => request('/papers/upload', { method: 'POST', body: formData }),
  getPapers: () => request('/papers/'),
  getPaper: (id) => request(`/papers/${id}`),

  // Exams
  getExams: () => request('/exams/'),
  getExam: (id) => request(`/exams/${id}`),
  createExam: (data) => request('/exams/', { method: 'POST', body: JSON.stringify(data) }),
  assignGuardian: (id, data) => request(`/exams/${id}/guardians`, { method: 'POST', body: JSON.stringify(data) }),
  stagePaper: (id, data) => request(`/exams/${id}/stage-paper`, { method: 'POST', body: JSON.stringify(data) }),
  stagePayload: (id, data) => request(`/exams/${id}/stage-payload`, { method: 'POST', body: JSON.stringify(data) }),

  // Consensus
  submitApproval: (id, data) => {
    const payload = typeof data === 'string' ? { share_token: data } : data;
    return request(`/consensus/${id}/approve`, { method: 'POST', body: JSON.stringify(payload) });
  },
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

  // Audit & Simulation
  getAuditEvents: (examId) => request(examId ? `/audit/events?exam_id=${examId}` : '/audit/events'),
  logAuditEvent: (data) => request('/audit/events', { method: 'POST', body: JSON.stringify(data) }),
  runSimulation: (data) => request('/simulation/run', { method: 'POST', body: JSON.stringify(data) }),
};
