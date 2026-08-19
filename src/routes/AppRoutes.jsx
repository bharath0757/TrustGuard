import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from '../components/layout';
import { ProtectedRoute } from '../components/auth';
import { LoginPage } from '../pages/LoginPage';
import { 
  DashboardPage, 
  PapersPage, 
  PaperDetailsPage,
  ApprovalsPage, 
  ThreatAlertsPage,
  AttackSimulatorPage,
  AuditPage, 
  ExamCenterPage,
  LiveExamPage,
  ExamReportPage,
  StudentExamPortalPage,
  NotFoundPage 
} from '../pages';

// Role groups for access control
const ADMIN_ROLES = ['ADMIN', 'EXAM_SETTER'];
const GUARDIAN_ROLES = ['ADMIN', 'EXAM_SETTER', 'KEY_GUARDIAN', 'AUDITOR'];
const EXAM_OPS_ROLES = ['ADMIN', 'EXAM_SETTER', 'EXAM_CENTER'];
const MONITOR_ROLES = ['ADMIN', 'EXAM_SETTER', 'KEY_GUARDIAN', 'EXAM_CENTER', 'AUDITOR'];
const ALL_STAFF_ROLES = ['ADMIN', 'EXAM_SETTER', 'KEY_GUARDIAN', 'EXAM_CENTER', 'AUDITOR', 'ATTACKER'];
const STUDENT_ROLES = ['STUDENT', 'ADMIN'];
const ATTACKER_ROLES = ['ATTACKER', 'ADMIN'];

export function AppRoutes() {
  return (
    <Routes>
      {/* Public: Login page (no layout) */}
      <Route path="/login" element={<LoginPage />} />

      {/* Student Standalone Exam Portal (Distraction-Free) */}
      <Route path="/student/exam" element={
        <ProtectedRoute allowedRoles={STUDENT_ROLES}>
          <StudentExamPortalPage />
        </ProtectedRoute>
      } />
      <Route path="/student/exam/:examId" element={
        <ProtectedRoute allowedRoles={STUDENT_ROLES}>
          <StudentExamPortalPage />
        </ProtectedRoute>
      } />

      {/* Protected: All staff app routes inside Layout */}
      <Route path="/" element={
        <ProtectedRoute>
          <Layout />
        </ProtectedRoute>
      }>
        {/* Dashboard — visible to all authenticated staff */}
        <Route index element={<DashboardPage />} />

        {/* Papers — admin/setter/guardians/auditor */}
        <Route path="papers" element={
          <ProtectedRoute allowedRoles={[...GUARDIAN_ROLES, 'EXAM_CENTER']}>
            <PapersPage />
          </ProtectedRoute>
        } />
        <Route path="papers/:paperId" element={
          <ProtectedRoute allowedRoles={[...GUARDIAN_ROLES, 'EXAM_CENTER']}>
            <PaperDetailsPage />
          </ProtectedRoute>
        } />

        {/* Approvals — guardians and admin */}
        <Route path="approvals" element={
          <ProtectedRoute allowedRoles={GUARDIAN_ROLES}>
            <ApprovalsPage />
          </ProtectedRoute>
        } />

        {/* Threat Alerts — staff (not students) */}
        <Route path="threat-alerts" element={
          <ProtectedRoute allowedRoles={ALL_STAFF_ROLES}>
            <ThreatAlertsPage />
          </ProtectedRoute>
        } />

        {/* Attack Simulator — attacker and admin */}
        <Route path="attack-simulator" element={
          <ProtectedRoute allowedRoles={ATTACKER_ROLES}>
            <AttackSimulatorPage />
          </ProtectedRoute>
        } />

        {/* Audit Trail — admin/auditor/guardians */}
        <Route path="audit" element={
          <ProtectedRoute allowedRoles={GUARDIAN_ROLES}>
            <AuditPage />
          </ProtectedRoute>
        } />

        {/* Exam Center — exam ops + students can view */}
        <Route path="exam-center" element={<ExamCenterPage />} />

        {/* Live Exam — accessible to all (students see exam, staff monitor) */}
        <Route path="live-exam/:examId" element={<LiveExamPage />} />

        {/* Exam Report — admin/setter/auditor/guardians */}
        <Route path="exam-report/:examId" element={
          <ProtectedRoute allowedRoles={[...GUARDIAN_ROLES, 'EXAM_CENTER']}>
            <ExamReportPage />
          </ProtectedRoute>
        } />
        
        {/* Convenience and Compatibility redirects */}
        <Route path="guardian" element={<Navigate to="/approvals" replace />} />
        <Route path="student" element={<Navigate to="/student/exam" replace />} />
        <Route path="attacker" element={<Navigate to="/attack-simulator" replace />} />
        <Route path="report/:examId" element={<Navigate to="/exam-report/:examId" replace />} />
        <Route path="reports/:examId" element={<Navigate to="/exam-report/:examId" replace />} />
        <Route path="exam-reports/:examId" element={<Navigate to="/exam-report/:examId" replace />} />
        <Route path="alerts" element={<Navigate to="/threat-alerts" replace />} />
        <Route path="settings" element={<Navigate to="/exam-center" replace />} />
        
        {/* 404 Route */}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
