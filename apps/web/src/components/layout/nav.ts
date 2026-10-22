import {
  BarChart3,
  Bug,
  FileText,
  Globe,
  LayoutDashboard,
  Radar,
  Server,
  Settings,
  type LucideIcon,
} from 'lucide-react';

export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  description: string;
  /** Milestone in which the page becomes functional, shown on placeholder pages. */
  milestone: string;
}

export const NAV_ITEMS: readonly NavItem[] = [
  {
    path: '/',
    label: 'Overview',
    icon: LayoutDashboard,
    description: 'Exposure summary, open findings and operational health.',
    milestone: 'Milestone 10',
  },
  {
    path: '/domains',
    label: 'Domains',
    icon: Globe,
    description: 'Registered domain inventory, ownership verification and registration monitoring.',
    milestone: 'Milestone 3',
  },
  {
    path: '/assets',
    label: 'Assets',
    icon: Server,
    description: 'Hostnames, IP history and the discovery approval queue.',
    milestone: 'Milestone 9',
  },
  {
    path: '/scans',
    label: 'Scans',
    icon: Radar,
    description: 'Scan profiles, job progress and scan history.',
    milestone: 'Milestone 4',
  },
  {
    path: '/findings',
    label: 'Findings',
    icon: Bug,
    description: 'Evidence-backed findings and the remediation workflow.',
    milestone: 'Milestone 8',
  },
  {
    path: '/advisories',
    label: 'Advisories',
    icon: FileText,
    description: 'Remediation advisories derived from findings and evidence.',
    milestone: 'Milestone 8',
  },
  {
    path: '/reports',
    label: 'Reports',
    icon: BarChart3,
    description: 'Exposure trends and exportable summaries.',
    milestone: 'Milestone 10',
  },
  {
    path: '/settings',
    label: 'Settings',
    icon: Settings,
    description: 'Users and roles, scan policies, worker health and integrations.',
    milestone: 'Milestone 10',
  },
];
