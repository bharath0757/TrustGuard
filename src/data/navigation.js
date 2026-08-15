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
  },
  {
    name: 'Question Papers',
    path: '/papers',
    icon: FileText,
    badge: '12',
  },
  {
    name: 'Approvals',
    path: '/approvals',
    icon: CheckSquare,
    badge: '3',
    badgeVariant: 'warning',
  },
  {
    name: 'Threat Alerts',
    path: '/threat-alerts',
    icon: ShieldAlert,
    badge: '3',
    badgeVariant: 'danger',
  },
  {
    name: 'Attack Simulator',
    path: '/attack-simulator',
    icon: ShieldX,
    badge: null,
  },
  {
    name: 'Audit Trail',
    path: '/audit',
    icon: History,
    badge: null,
  },
  {
    name: 'Exam Center',
    path: '/exam-center',
    icon: Building2,
    badge: null,
  },
];

export const MAIN_NAVIGATION = NAVIGATION_ITEMS;
