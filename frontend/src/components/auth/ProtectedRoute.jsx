import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { ShieldCheck, Loader2 } from 'lucide-react';

/**
 * ProtectedRoute — wraps routes that require authentication.
 *
 * Props:
 *   allowedRoles: optional array of role strings. If provided, user must have one of these roles.
 *   children: the protected content to render.
 *
 * Behavior:
 *   - If not authenticated → redirect to /login
 *   - If authenticated but wrong role → show access denied
 *   - If authenticated and authorized → render children
 */
export function ProtectedRoute({ allowedRoles, children }) {
  const { isAuthenticated, loading, role, roleLabel } = useAuth();
  const location = useLocation();

  // Show loading state during initial auth check
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F5F7FA]">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 text-[#17324D] animate-spin" />
          <p className="text-sm text-[#5E6B78]">Verifying credentials…</p>
        </div>
      </div>
    );
  }

  // Not authenticated → redirect to login
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Role check (if allowedRoles specified)
  if (allowedRoles && allowedRoles.length > 0 && !allowedRoles.includes(role)) {
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="text-center max-w-md">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#FDF2F2] border border-[#FECDCA] mb-4">
            <ShieldCheck className="w-6 h-6 text-[#C44747]" />
          </div>
          <h2 className="text-lg font-semibold text-[#17324D] mb-2">Access Restricted</h2>
          <p className="text-sm text-[#5E6B78] mb-4">
            Your role <span className="font-semibold text-[#17324D]">({roleLabel})</span> does not have permission to access this page.
          </p>
          <p className="text-xs text-[#98A2B3]">
            Required: {allowedRoles.map((r) => r.replace('_', ' ')).join(', ')}
          </p>
        </div>
      </div>
    );
  }

  return children;
}
