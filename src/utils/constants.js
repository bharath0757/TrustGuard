/**
 * TrustGuard System Constants (Frontend Only)
 * High-stakes examination question paper security lifecycle classifications.
 */

export const APP_NAME = 'TrustGuard';
export const APP_TAGLINE = 'Examination Question Paper Security';
export const APP_VERSION = 'v1.0.0';

export const USER_ROLES = {
  INVIGILATOR: { id: 'R1', label: 'Exam Centre Invigilator', color: 'blue' },
  CHIEF_EXAMINER: { id: 'R2', label: 'Chief Examiner', color: 'emerald' },
  KEY_CUSTODIAN: { id: 'R3', label: 'Authorized Officer (Quorum Member)', color: 'navy' },
  SECURITY_OFFICER: { id: 'R4', label: 'Security Administrator', color: 'amber' },
  MASTER_AUDITOR: { id: 'R5', label: 'Audit & Compliance Officer', color: 'slate' },
};

export const PAPER_STATUSES = {
  ENCRYPTED_SEALED: { 
    id: 'ENCRYPTED_SEALED',
    label: 'Protected & Sealed', 
    description: 'Stored in isolated secure storage nodes; access keys fragmented.',
    variant: 'info' 
  },
  PENDING_APPROVAL: { 
    id: 'PENDING_APPROVAL',
    label: 'Pending Approvals', 
    description: 'Awaiting quorum signatures from designated authorized officers.',
    variant: 'warning' 
  },
  AUTHORIZED_RELEASE: { 
    id: 'AUTHORIZED_RELEASE',
    label: 'Authorized for Exam Release', 
    description: 'Quorum reached. Access permitted during scheduled exam time window.',
    variant: 'success' 
  },
  SECURITY_HOLD: { 
    id: 'SECURITY_HOLD',
    label: 'Security Hold', 
    description: 'Access blocked due to security alert or policy failure.',
    variant: 'danger' 
  },
  ARCHIVED: { 
    id: 'ARCHIVED',
    label: 'Exam Completed & Closed', 
    description: 'Examination finished; access session closed and audit log sealed.',
    variant: 'neutral' 
  },
};

export const ALERT_SEVERITIES = {
  CRITICAL: { 
    label: 'Critical', 
    color: 'red', 
    bg: 'bg-[#FEF3F2]', 
    text: 'text-[#C44747]', 
    border: 'border-[#FECDCA]',
    badgeVariant: 'danger',
  },
  HIGH: { 
    label: 'High Risk', 
    color: 'amber', 
    bg: 'bg-[#FFFAEB]', 
    text: 'text-[#B7791F]', 
    border: 'border-[#FEDF89]',
    badgeVariant: 'warning',
  },
  MEDIUM: { 
    label: 'Warning', 
    color: 'amber', 
    bg: 'bg-[#FFFAEB]', 
    text: 'text-[#B7791F]', 
    border: 'border-[#FEDF89]',
    badgeVariant: 'warning',
  },
  LOW: { 
    label: 'Information', 
    color: 'navy', 
    bg: 'bg-[#F0F5F9]', 
    text: 'text-[#17324D]', 
    border: 'border-[#D8E6F0]',
    badgeVariant: 'info',
  },
};

export const LIFECYCLE_STAGES = [
  { step: 1, name: 'Paper Created', desc: 'Secure encryption upon registration' },
  { step: 2, name: 'Fragmentation', desc: 'Secret sharing splits key into fragments' },
  { step: 3, name: 'Distribution', desc: 'Fragments distributed across isolated nodes' },
  { step: 4, name: 'Quorum Authorization', desc: 'Officers sign off before exam window' },
  { step: 5, name: 'Exam Window Release', desc: 'Decryption unlocked during scheduled exam' },
  { step: 6, name: 'Session Closed', desc: 'Access terminated, permanent audit log sealed' },
];
