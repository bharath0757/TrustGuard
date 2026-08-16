import React, { createContext, useState, useEffect } from 'react';

export const TrustGuardContext = createContext(null);

const INITIAL_PAPER = {
  id: 'JEE-MOCK-001',
  name: 'Engineering Entrance Examination',
  security: 'Protected',
  encryption: 'Complete',
  fragmentation: 'Complete',
  distribution: 'Complete',
  requiredApprovals: 3,
  currentApprovals: 2,
  decryption: 'Locked',
  examAccess: 'Locked', // 'Locked' | 'Ready' | 'Active' | 'Closed'
  examWindow: '09:55 – 12:00',
  lastUpdated: '09:42',
};

const INITIAL_OFFICERS = {
  officerA: { name: 'Officer A', role: 'Examination Controller', status: 'Approved', time: '09:44' },
  officerB: { name: 'Officer B', role: 'Regional Coordinator', status: 'Approved', time: '09:44' },
  officerC: { name: 'Officer C', role: 'Examination Officer', status: 'Pending', time: null },
};

const INITIAL_PAPERS_LIST = [
  {
    id: 'JEE-MOCK-001',
    examination: 'Engineering Entrance Examination',
    securityStatus: 'Protected',
    approvals: '2 / 3',
    access: 'Locked',
    lastUpdated: '09:42',
  },
  {
    id: 'NEET-MOCK-002',
    examination: 'Medical Entrance Examination',
    securityStatus: 'Protected',
    approvals: '2 / 3',
    access: 'Locked',
    lastUpdated: '09:47',
  },
  {
    id: 'EXAM-MOCK-003',
    examination: 'National Scholarship Examination',
    securityStatus: 'Pending',
    approvals: '1 / 3',
    access: 'Locked',
    lastUpdated: '10:02',
  },
  {
    id: 'DEMO-004',
    examination: 'TrustGuard Demonstration',
    securityStatus: 'Protected',
    approvals: '3 / 3',
    access: 'Authorized',
    lastUpdated: '10:15',
  },
];

// Pristine baseline alerts with 0 active threats
const INITIAL_THREAT_ALERTS = [
  {
    id: 'ALT-104',
    severity: 'Resolved',
    title: 'Terminal clock synchronization verification',
    paper: 'DEMO-004',
    action: 'Time verification check',
    result: 'Re-synchronized',
    time: '08:30',
    status: 'Resolved',
    authorization: 'Passed',
    decision: 'RESOLVED',
    decisionStatus: 'Recorded',
    reason: 'Terminal time drift corrected against official time standard.',
    timeline: [
      { time: '08:30:00', text: 'Time verification initiated' },
      { time: '08:30:02', text: 'Sync check completed' },
      { time: '08:30:04', text: 'Official time synchronized' },
      { time: '08:30:05', text: 'Verification logged' },
    ],
  },
  {
    id: 'ALT-105',
    severity: 'Resolved',
    title: 'Print station certificate verification',
    paper: 'BAR-MOCK-005',
    action: 'Station handshake',
    result: 'Verified',
    time: '08:15',
    status: 'Resolved',
    authorization: 'Passed',
    decision: 'RESOLVED',
    decisionStatus: 'Recorded',
    reason: 'Station identity certificate verified successfully.',
    timeline: [
      { time: '08:15:01', text: 'Handshake initiated' },
      { time: '08:15:02', text: 'Certificate verified' },
      { time: '08:15:03', text: 'Station activated' },
    ],
  },
];

// Pristine baseline audit log
const INITIAL_AUDIT_EVENTS = [
  {
    id: 'EVT-1002',
    time: '09:44:21',
    type: 'Approval',
    actor: 'Officer B',
    paper: 'JEE-MOCK-001',
    action: 'Approval recorded',
    result: 'Success',
    description: 'Officer B (Regional Coordinator) successfully submitted authorization signature.',
    requestedAction: 'Sign authorization request',
  },
  {
    id: 'EVT-1003',
    time: '09:43:18',
    type: 'Paper',
    actor: 'System',
    paper: 'JEE-MOCK-001',
    action: 'Fragmentation completed',
    result: 'Success',
    description: 'Question paper package split into 3 protected fragments and stored across nodes.',
    requestedAction: 'Generate and distribute fragments',
  },
  {
    id: 'EVT-1004',
    time: '09:42:04',
    type: 'System',
    actor: 'System',
    paper: 'JEE-MOCK-001',
    action: 'Paper registered',
    result: 'Success',
    description: 'New examination paper registered and initial security baseline created.',
    requestedAction: 'Register examination package',
  },
  {
    id: 'EVT-1006',
    time: '09:40:15',
    type: 'Approval',
    actor: 'Officer A',
    paper: 'JEE-MOCK-001',
    action: 'Approval recorded',
    result: 'Success',
    description: 'Officer A (Examination Controller) signed the initial authorization request.',
    requestedAction: 'Sign authorization request',
  },
  {
    id: 'EVT-1007',
    time: '09:38:00',
    type: 'Paper',
    actor: 'System',
    paper: 'NEET-MOCK-002',
    action: 'Encryption completed',
    result: 'Success',
    description: 'Medical entrance paper encrypted with zero-trust envelope protection.',
    requestedAction: 'Apply zero-trust encryption',
  },
  {
    id: 'EVT-1008',
    time: '09:35:12',
    type: 'System',
    actor: 'System',
    paper: 'DEMO-004',
    action: 'Integrity check completed',
    result: 'Success',
    description: 'Scheduled integrity verification confirmed all stored fragments are unaltered.',
    requestedAction: 'Verify storage node integrity',
  },
];

export function TrustGuardProvider({ children }) {
  const [paper, setPaper] = useState(INITIAL_PAPER);
  const [officers, setOfficers] = useState(INITIAL_OFFICERS);
  const [papersList, setPapersList] = useState(INITIAL_PAPERS_LIST);
  const [threatAlerts, setThreatAlerts] = useState(INITIAL_THREAT_ALERTS);
  const [auditEvents, setAuditEvents] = useState(INITIAL_AUDIT_EVENTS);
  const [activeThreatCount, setActiveThreatCount] = useState(0); // 0 active threats initially
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.innerWidth < 1024;
    }
    return false;
  });

  useEffect(() => {
    // Ensure dark mode class and attribute are removed from html element
    document.documentElement.classList.remove('dark');
    document.documentElement.removeAttribute('data-theme');
    localStorage.removeItem('trustguard-theme');
  }, []);

  const toggleSidebar = () => setSidebarCollapsed((prev) => !prev);

  // DEMO FLOW 2 — SIMULATE UNAUTHORIZED ACCESS
  const triggerAttackSimulation = ({ scenarioName, paperId }) => {
    const targetPaper = paperId || 'JEE-MOCK-001';
    const currentTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const fullTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    setActiveThreatCount((prev) => prev + 1);

    const newAlert = {
      id: `ALT-${Date.now().toString().slice(-4)}`,
      severity: 'Critical',
      title: 'Unauthorized question-paper access attempt',
      paper: targetPaper,
      action: 'Reconstruct protected paper',
      result: 'Access blocked',
      time: currentTime,
      status: 'Active',
      authorization: 'Failed',
      decision: 'ACCESS BLOCKED',
      decisionStatus: 'Recorded',
      reason: 'Required authorization was not satisfied.',
      timeline: [
        { time: `${currentTime}:01`, text: 'Access request received' },
        { time: `${currentTime}:01`, text: 'Authorization checked' },
        { time: `${currentTime}:02`, text: 'Required approval not satisfied' },
        { time: `${currentTime}:02`, text: 'Access blocked' },
        { time: `${currentTime}:03`, text: 'Security event recorded' },
      ],
    };

    const newAuditEvent = {
      id: `EVT-${Date.now().toString().slice(-4)}`,
      time: fullTime,
      type: 'Security',
      actor: 'Unknown User',
      paper: targetPaper,
      action: 'Unauthorized paper access request blocked',
      result: 'Blocked',
      description: 'The request did not satisfy the required authorization conditions.',
      requestedAction: 'Requested protected paper access',
    };

    setThreatAlerts((prev) => [newAlert, ...prev]);
    setAuditEvents((prev) => [newAuditEvent, ...prev]);
  };

  // DEMO FLOW 5 — FINAL QUORUM APPROVAL
  const completeFinalApproval = () => {
    const currentTime = '09:45';
    const fullTime = '09:45:00';

    setOfficers((prev) => ({
      ...prev,
      officerC: {
        ...prev.officerC,
        status: 'Approved',
        time: currentTime,
      },
    }));

    setPaper((prev) => ({
      ...prev,
      currentApprovals: 3,
      decryption: 'Authorized',
      examAccess: 'Ready',
    }));

    setPapersList((prev) =>
      prev.map((p) =>
        p.id === 'JEE-MOCK-001'
          ? { ...p, approvals: '3 / 3', access: 'Authorized' }
          : p
      )
    );

    const newAuditEvent = {
      id: `EVT-${Date.now().toString().slice(-4)}`,
      time: fullTime,
      type: 'Approval',
      actor: 'Officer C',
      paper: 'JEE-MOCK-001',
      action: 'Final approval received',
      result: 'Success',
      description: 'Officer C signed the authorization request. Quorum achieved (3 of 3).',
      requestedAction: 'Sign authorization request',
    };

    setAuditEvents((prev) => [newAuditEvent, ...prev]);
  };

  // DEMO FLOW 8 — OPEN SECURE SESSION
  const openSecurePaperSession = () => {
    const fullTime = '09:55:00';

    setPaper((prev) => ({
      ...prev,
      examAccess: 'Active',
    }));

    const newAuditEvent = {
      id: `EVT-${Date.now().toString().slice(-4)}`,
      time: fullTime,
      type: 'System',
      actor: 'Exam Center #1',
      paper: 'JEE-MOCK-001',
      action: 'Secure exam-paper access opened',
      result: 'Success',
      description: 'Authorized exam access session initialized inside verified examination terminal.',
      requestedAction: 'Open exam access session',
    };

    setAuditEvents((prev) => [newAuditEvent, ...prev]);
  };

  // DEMO FLOW 9 — CLOSE SESSION
  const closeSecurePaperSession = () => {
    const fullTime = '12:00:00';

    setPaper((prev) => ({
      ...prev,
      examAccess: 'Closed',
    }));

    const newAuditEvent = {
      id: `EVT-${Date.now().toString().slice(-4)}`,
      time: fullTime,
      type: 'System',
      actor: 'Exam Center #1',
      paper: 'JEE-MOCK-001',
      action: 'Exam-paper access session closed',
      result: 'Success',
      description: 'Exam-paper access session concluded and terminal memory purged.',
      requestedAction: 'Terminate exam session',
    };

    setAuditEvents((prev) => [newAuditEvent, ...prev]);
  };

  // RESET DEMO STATE — Returns to pristine initial demonstration state
  const resetDemoState = () => {
    setPaper(INITIAL_PAPER);
    setOfficers(INITIAL_OFFICERS);
    setPapersList(INITIAL_PAPERS_LIST);
    setThreatAlerts(INITIAL_THREAT_ALERTS);
    setAuditEvents(INITIAL_AUDIT_EVENTS);
    setActiveThreatCount(0);
  };

  const isQuorumAchieved = paper.currentApprovals >= paper.requiredApprovals;

  const value = {
    paper,
    officers,
    papersList,
    threatAlerts,
    auditEvents,
    activeThreatCount,
    isQuorumAchieved,
    triggerAttackSimulation,
    completeFinalApproval,
    openSecurePaperSession,
    closeSecurePaperSession,
    resetDemoState,
    sidebarCollapsed,
    toggleSidebar,
  };

  return (
    <TrustGuardContext.Provider value={value}>
      {children}
    </TrustGuardContext.Provider>
  );
}
