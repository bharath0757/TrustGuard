import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const AuthContext = createContext(null);

const API_BASE = '/api/v1';

// Role display labels and role-group helpers
const ROLE_LABELS = {
  ADMIN: 'Administrator',
  EXAM_SETTER: 'Exam Setter',
  KEY_GUARDIAN: 'Key Guardian',
  EXAM_CENTER: 'Exam Center',
  AUDITOR: 'Auditor',
  STUDENT: 'Student',
  ATTACKER: 'Security Tester',
};

// Role-based color tokens matching TrustGuard institutional theme
const ROLE_COLORS = {
  ADMIN: { bg: 'bg-[#17324D]', text: 'text-white', badge: 'bg-[#EAF2F8] text-[#17324D]' },
  EXAM_SETTER: { bg: 'bg-[#3E6B8C]', text: 'text-white', badge: 'bg-[#EAF2F8] text-[#3E6B8C]' },
  KEY_GUARDIAN: { bg: 'bg-[#2E7D5B]', text: 'text-white', badge: 'bg-[#EAF5F0] text-[#2E7D5B]' },
  EXAM_CENTER: { bg: 'bg-[#5B21B6]', text: 'text-white', badge: 'bg-[#F3F0FF] text-[#5B21B6]' },
  AUDITOR: { bg: 'bg-[#5E6B78]', text: 'text-white', badge: 'bg-[#F0F4F8] text-[#5E6B78]' },
  STUDENT: { bg: 'bg-[#0369A1]', text: 'text-white', badge: 'bg-[#E0F2FE] text-[#0369A1]' },
  ATTACKER: { bg: 'bg-[#C44747]', text: 'text-white', badge: 'bg-[#FDF2F2] text-[#C44747]' },
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);        // { id, username, email, role, created_at }
  const [token, setToken] = useState(null);       // JWT string
  const [loading, setLoading] = useState(true);   // Initial auth check
  const [error, setError] = useState(null);

  // On mount: restore session from localStorage
  useEffect(() => {
    const savedToken = localStorage.getItem('trustguard_token');
    const savedUser = localStorage.getItem('trustguard_user');
    if (savedToken && savedUser) {
      try {
        const parsed = JSON.parse(savedUser);
        setToken(savedToken);
        setUser(parsed);
      } catch {
        localStorage.removeItem('trustguard_token');
        localStorage.removeItem('trustguard_user');
      }
    }
    setLoading(false);
  }, []);

  // Login
  const login = useCallback(async (username, password) => {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Login failed');
      }

      const data = await res.json();
      const accessToken = data.access_token;

      // Fetch user profile
      const meRes = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!meRes.ok) {
        throw new Error('Failed to fetch user profile');
      }

      const userData = await meRes.json();

      // Persist session
      localStorage.setItem('trustguard_token', accessToken);
      localStorage.setItem('trustguard_user', JSON.stringify(userData));
      setToken(accessToken);
      setUser(userData);

      return userData;
    } catch (err) {
      setError(err.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  // Logout
  const logout = useCallback(() => {
    localStorage.removeItem('trustguard_token');
    localStorage.removeItem('trustguard_user');
    setToken(null);
    setUser(null);
    setError(null);
  }, []);

  // Auth headers helper
  const getAuthHeaders = useCallback(() => {
    if (!token) return {};
    return { Authorization: `Bearer ${token}` };
  }, [token]);

  // Derived state
  const isAuthenticated = !!user && !!token;
  const role = user?.role || null;
  const roleLabel = ROLE_LABELS[role] || role || 'Unknown';
  const roleColor = ROLE_COLORS[role] || ROLE_COLORS.ADMIN;

  // Role checks
  const isAdmin = role === 'ADMIN';
  const isGuardian = role === 'KEY_GUARDIAN';
  const isStudent = role === 'STUDENT';
  const isAttacker = role === 'ATTACKER';
  const isExamCenter = role === 'EXAM_CENTER';
  const isAuditor = role === 'AUDITOR';
  const isExamSetter = role === 'EXAM_SETTER';

  // Check if user has one of the given roles
  const hasRole = useCallback(
    (roles) => roles.includes(role),
    [role]
  );

  const value = {
    // State
    user,
    token,
    loading,
    error,
    isAuthenticated,

    // Role info
    role,
    roleLabel,
    roleColor,
    isAdmin,
    isGuardian,
    isStudent,
    isAttacker,
    isExamCenter,
    isAuditor,
    isExamSetter,
    hasRole,

    // Actions
    login,
    logout,
    getAuthHeaders,
    setError,

    // Constants
    ROLE_LABELS,
    ROLE_COLORS,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export { AuthContext, ROLE_LABELS, ROLE_COLORS };
