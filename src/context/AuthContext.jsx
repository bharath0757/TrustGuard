import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api, getToken, setToken, removeToken } from '../api/client';

const AuthContext = createContext(null);

// Role display configuration
const ROLE_CONFIG = {
  ADMIN: { label: 'Administrator', color: { bg: 'bg-purple-600', badge: 'bg-purple-100 text-purple-700' } },
  EXAM_SETTER: { label: 'Exam Setter', color: { bg: 'bg-blue-600', badge: 'bg-blue-100 text-blue-700' } },
  KEY_GUARDIAN: { label: 'Key Guardian', color: { bg: 'bg-emerald-600', badge: 'bg-emerald-100 text-emerald-700' } },
  EXAM_CENTER: { label: 'Exam Center', color: { bg: 'bg-amber-600', badge: 'bg-amber-100 text-amber-700' } },
  AUDITOR: { label: 'Auditor', color: { bg: 'bg-cyan-600', badge: 'bg-cyan-100 text-cyan-700' } },
  STUDENT: { label: 'Student', color: { bg: 'bg-green-600', badge: 'bg-green-100 text-green-700' } },
  ATTACKER: { label: 'Attacker', color: { bg: 'bg-red-600', badge: 'bg-red-100 text-red-700' } },
};

const DEFAULT_COLOR = { bg: 'bg-gray-600', badge: 'bg-gray-100 text-gray-700' };

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Restore session on mount
  useEffect(() => {
    const token = getToken();
    if (token) {
      api.getMe()
        .then((userData) => setUser(userData))
        .catch(() => {
          removeToken();
          setUser(null);
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = useCallback(async (credentials) => {
    const data = await api.login(credentials);
    if (data.access_token) {
      setToken(data.access_token);
      const userData = await api.getMe();
      setUser(userData);
      return userData;
    }
    throw new Error('Login failed');
  }, []);

  const register = useCallback(async (userData) => {
    const data = await api.register(userData);
    return data;
  }, []);

  const logout = useCallback(() => {
    removeToken();
    setUser(null);
  }, []);

  const role = user?.role || 'STUDENT';
  const config = ROLE_CONFIG[role] || { label: role, color: DEFAULT_COLOR };
  const roleLabel = config.label;
  const roleColor = config.color;

  const isAdmin = role === 'ADMIN';
  const isGuardian = role === 'KEY_GUARDIAN' || isAdmin;
  const isExamSetter = role === 'EXAM_SETTER' || isAdmin;
  const isStudent = role === 'STUDENT';
  const isAttacker = role === 'ATTACKER';
  const isAuthenticated = !!user;

  const value = {
    user,
    loading,
    role,
    roleLabel,
    roleColor,
    isAdmin,
    isGuardian,
    isExamSetter,
    isStudent,
    isAttacker,
    isAuthenticated,
    login,
    register,
    logout,
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
    // Return safe defaults if used outside provider (e.g., during initial render)
    return {
      user: null,
      loading: false,
      role: 'STUDENT',
      roleLabel: 'Student',
      roleColor: DEFAULT_COLOR,
      isAdmin: false,
      isGuardian: false,
      isExamSetter: false,
      isStudent: true,
      isAttacker: false,
      isAuthenticated: false,
      login: async () => {},
      register: async () => {},
      logout: () => {},
    };
  }
  return context;
}
