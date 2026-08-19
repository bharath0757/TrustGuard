import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Eye, EyeOff, Loader2, Users, AlertCircle, ChevronDown } from 'lucide-react';
import { useAuth, ROLE_LABELS, ROLE_COLORS } from '../context/AuthContext';

// Demo user quick-login presets
const DEMO_ACCOUNTS = [
  { username: 'admin', role: 'ADMIN', label: 'Administrator', desc: 'Full system access' },
  { username: 'guardian1', role: 'KEY_GUARDIAN', label: 'Guardian 1', desc: 'Quorum approval authority' },
  { username: 'guardian2', role: 'KEY_GUARDIAN', label: 'Guardian 2', desc: 'Quorum approval authority' },
  { username: 'guardian3', role: 'KEY_GUARDIAN', label: 'Guardian 3', desc: 'Quorum approval authority' },
  { username: 'student1', role: 'STUDENT', label: 'Student 1', desc: 'Exam participant' },
  { username: 'student2', role: 'STUDENT', label: 'Student 2', desc: 'Exam participant' },
  { username: 'attacker', role: 'ATTACKER', label: 'Security Tester', desc: 'Controlled attack simulation' },
  { username: 'examcenter', role: 'EXAM_CENTER', label: 'Exam Center', desc: 'Paper distribution terminal' },
];

export function LoginPage() {
  const navigate = useNavigate();
  const { login, user, isAuthenticated, loading, error, setError } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showQuickLogin, setShowQuickLogin] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [seedMessage, setSeedMessage] = useState(null);

  const redirectByRole = (userData) => {
    if (!userData) return;
    if (userData.role === 'STUDENT') {
      navigate('/student/exam', { replace: true });
    } else if (userData.role === 'ATTACKER') {
      navigate('/attack-simulator', { replace: true });
    } else {
      navigate('/', { replace: true });
    }
  };

  // Redirect if already logged in based on role
  useEffect(() => {
    if (isAuthenticated && user) {
      redirectByRole(user);
    }
  }, [isAuthenticated, user]);

  // Auto-seed on mount
  useEffect(() => {
    const seedDemoUsers = async () => {
      setSeeding(true);
      try {
        const res = await fetch('/api/v1/users/seed', { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          if (data.created?.length > 0) {
            setSeedMessage(`${data.created.length} demo accounts initialized`);
          }
        }
      } catch {
        // Seed failure is non-critical — users may already exist
      } finally {
        setSeeding(false);
      }
    };
    seedDemoUsers();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password');
      return;
    }
    const loggedInUser = await login(username, password);
    if (loggedInUser) {
      redirectByRole(loggedInUser);
    }
  };

  const handleQuickLogin = async (account) => {
    setUsername(account.username);
    setPassword('trustguard123');
    setError(null);

    const loggedInUser = await login(account.username, 'trustguard123');
    if (loggedInUser) {
      redirectByRole(loggedInUser);
    }
  };

  const getRoleIcon = (role) => {
    const colors = ROLE_COLORS[role] || ROLE_COLORS.ADMIN;
    return (
      <div className={`w-8 h-8 rounded-lg ${colors.bg} flex items-center justify-center text-white text-xs font-bold shrink-0`}>
        {role === 'ADMIN' ? 'A' : role === 'KEY_GUARDIAN' ? 'G' : role === 'STUDENT' ? 'S' : role === 'ATTACKER' ? '⚡' : role === 'EXAM_CENTER' ? 'E' : '?'}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-[#F5F7FA] flex items-center justify-center p-4 relative overflow-hidden font-sans antialiased">
      {/* Ambient Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute w-125 h-125 rounded-full bg-[#17324D]/3 -top-40 -left-40 animate-bubble-slow" />
        <div className="absolute w-100 h-100 rounded-full bg-[#3E6B8C]/3 -bottom-32 -right-32 animate-bubble-reverse" />
        <div className="absolute w-75 h-75 rounded-full bg-[#2E7D5B]/3 top-1/3 right-1/4 animate-bubble-drift" />
      </div>

      <div className="relative z-10 w-full max-w-md">
        {/* Logo Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-[#17324D] shadow-lg mb-4">
            <ShieldCheck className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-[#17324D] tracking-tight">TrustGuard</h1>
          <p className="text-sm text-[#5E6B78] mt-1">Secure Examination Distribution Platform</p>
        </div>

        {/* Login Card */}
        <div className="bg-white rounded-xl border border-[#C7D0DA] shadow-sm p-6 sm:p-8">
          <h2 className="text-base font-semibold text-[#17324D] mb-1">Sign in to your account</h2>
          <p className="text-xs text-[#5E6B78] mb-6">Enter credentials or use a demo account below</p>

          {/* Error Alert */}
          {error && (
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-[#FDF2F2] border border-[#FECDCA] mb-4">
              <AlertCircle className="w-4 h-4 text-[#C44747] shrink-0 mt-0.5" />
              <p className="text-xs text-[#C44747] font-medium">{error}</p>
            </div>
          )}

          {/* Seed Status */}
          {seedMessage && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#EAF5F0] border border-[#D1FADF] mb-4">
              <span className="w-2 h-2 rounded-full bg-[#2E7D5B]" />
              <p className="text-xs text-[#2E7D5B] font-medium">{seedMessage}</p>
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="login-username" className="block text-xs font-medium text-[#344054] mb-1.5">
                Username
              </label>
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                className="w-full px-3.5 py-2.5 bg-white border border-[#C7D0DA] rounded-lg text-sm text-[#182230] placeholder:text-[#98A2B3] focus:outline-none focus:ring-2 focus:ring-[#17324D]/20 focus:border-[#17324D] transition-colors"
                autoComplete="username"
                autoFocus
              />
            </div>

            <div>
              <label htmlFor="login-password" className="block text-xs font-medium text-[#344054] mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full px-3.5 py-2.5 pr-10 bg-white border border-[#C7D0DA] rounded-lg text-sm text-[#182230] placeholder:text-[#98A2B3] focus:outline-none focus:ring-2 focus:ring-[#17324D]/20 focus:border-[#17324D] transition-colors"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#98A2B3] hover:text-[#5E6B78] transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-[#17324D] text-white text-sm font-semibold rounded-lg hover:bg-[#1e405f] active:bg-[#0f2438] disabled:opacity-60 disabled:cursor-not-allowed transition-colors shadow-sm cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Signing in…
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Separator */}
          <div className="flex items-center gap-3 my-6">
            <div className="flex-1 h-px bg-[#E4E7EC]" />
            <span className="text-xs text-[#98A2B3] font-medium">OR USE DEMO ACCOUNT</span>
            <div className="flex-1 h-px bg-[#E4E7EC]" />
          </div>

          {/* Quick Login Grid */}
          <button
            type="button"
            onClick={() => setShowQuickLogin(!showQuickLogin)}
            className="w-full flex items-center justify-between px-3.5 py-2.5 bg-[#F0F4F8] border border-[#C7D0DA] rounded-lg text-sm font-medium text-[#17324D] hover:bg-[#EAF2F8] transition-colors cursor-pointer"
          >
            <span className="flex items-center gap-2">
              <Users className="w-4 h-4" />
              Demo Accounts ({DEMO_ACCOUNTS.length} users)
            </span>
            <ChevronDown className={`w-4 h-4 transition-transform ${showQuickLogin ? 'rotate-180' : ''}`} />
          </button>

          {showQuickLogin && (
            <div className="mt-3 grid grid-cols-2 gap-2">
              {DEMO_ACCOUNTS.map((account) => {
                const colors = ROLE_COLORS[account.role] || ROLE_COLORS.ADMIN;
                return (
                  <button
                    key={account.username}
                    type="button"
                    onClick={() => handleQuickLogin(account)}
                    disabled={loading || seeding}
                    className="flex items-center gap-2.5 p-2.5 bg-white border border-[#D5DDE5] rounded-lg text-left hover:border-[#17324D] hover:shadow-sm transition-all disabled:opacity-50 group cursor-pointer"
                  >
                    {getRoleIcon(account.role)}
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-[#182230] truncate group-hover:text-[#17324D]">
                        {account.label}
                      </div>
                      <div className={`text-[10px] font-medium truncate ${colors.badge.split(' ')[1]}`}>
                        {account.desc}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-[#98A2B3] mt-6">
          TrustGuard Secure Examination Platform — Demo Mode
        </p>
      </div>
    </div>
  );
}
