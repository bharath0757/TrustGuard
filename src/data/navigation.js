import { 
  LayoutDashboard, 
  FileText, 
  CheckSquare, 
  ShieldAlert, 
  ShieldX, 
  History, 
  Building2 
} from 'lucide-react';

export const NAVIGATION_ITEMS = [
  {
    name: 'Dashboard',
    path: '/',
    icon: LayoutDashboard,
    badge: null,
    roles: null, // visible to all authenticated users
  },
  {
    name: 'Question Papers',
    path: '/papers',
    icon: FileText,
    badge: null,
    roles: ['ADMIN', 'EXAM_SETTER', 'KEY_GUARDIAN', 'EXAM_CENTER', 'AUDITOR'],
  },
  {
    name: 'Approvals',
    path: '/approvals',
    icon: CheckSquare,
    badge: null,
    badgeVariant: 'warning',
    roles: ['ADMIN', 'EXAM_SETTER', 'KEY_GUARDIAN', 'AUDITOR'],
  },
  {
    name: 'Threat Alerts',
    path: '/threat-alerts',
    icon: ShieldAlert,
    badge: null,
    badgeVariant: 'danger',
    roles: ['ADMIN', 'EXAM_SETTER', 'KEY_GUARDIAN', 'EXAM_CENTER', 'AUDITOR', 'ATTACKER'],
  },
  {
    name: 'Attack Simulator',
    path: '/attack-simulator',
    icon: ShieldX,
    badge: null,
    roles: ['ATTACKER', 'ADMIN'],
  },
  {
    name: 'Audit Trail',
    path: '/audit',
    icon: History,
    badge: null,
    roles: ['ADMIN', 'EXAM_SETTER', 'KEY_GUARDIAN', 'AUDITOR'],
  },
  {
    name: 'Exam Center',
    path: '/exam-center',
    icon: Building2,
    badge: null,
    roles: null, // visible to all authenticated users
  },
];

/**
 * Filter navigation items by user role.
 * Items with roles=null are visible to all authenticated users.
 */
export function getNavigationForRole(role) {
  if (!role) return [];
  return NAVIGATION_ITEMS.filter(
    (item) => item.roles === null || item.roles.includes(role)
  );
}

export const MAIN_NAVIGATION = NAVIGATION_ITEMS;
