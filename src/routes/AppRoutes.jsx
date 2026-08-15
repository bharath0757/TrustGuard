import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from '../components/layout';
import { 
  DashboardPage, 
  PapersPage, 
  PaperDetailsPage,
  ApprovalsPage, 
  ThreatAlertsPage,
  AttackSimulatorPage,
  AuditPage, 
  ExamCenterPage,
  NotFoundPage 
} from '../pages';

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="papers" element={<PapersPage />} />
        <Route path="papers/:paperId" element={<PaperDetailsPage />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="threat-alerts" element={<ThreatAlertsPage />} />
        <Route path="attack-simulator" element={<AttackSimulatorPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="exam-center" element={<ExamCenterPage />} />
        
        {/* Compatibility redirects */}
        <Route path="alerts" element={<Navigate to="/threat-alerts" replace />} />
        <Route path="settings" element={<Navigate to="/exam-center" replace />} />
        
        {/* 404 Route */}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
