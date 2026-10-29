import {
  BarChart3,
  Boxes,
  DoorOpen,
  FileLock2,
  Network,
  ShieldAlert,
  Bug,
  FileText,
  Globe,
  History,
  LayoutDashboard,
  Package,
  Radar,
  ScanSearch,
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
    path: '/subdomains',
    label: 'Subdomains',
    icon: Network,
    description: 'Subdomains of every domain, how they were found and what they appear to run.',
    milestone: 'Milestone 13',
  },
  {
    path: '/assets',
    label: 'Assets',
    icon: Server,
    description: 'Hostnames, IP history and the discovery approval queue.',
    milestone: 'Milestone 9',
  },
  {
    path: '/ports',
    label: 'Open Ports',
    icon: DoorOpen,
    description: 'Ports observed on approved networks, with services and exposure policy.',
    milestone: 'Milestone 13',
  },
  {
    path: '/certificates',
    label: 'Certificates',
    icon: FileLock2,
    description: 'TLS certificates in use, their issuers and expiry.',
    milestone: 'Milestone 13',
  },
  {
    path: '/software',
    label: 'Software',
    icon: Package,
    description: 'Self-reported software versions with end-of-life and known-exploited matches.',
    milestone: 'Milestone 11',
  },
  {
    path: '/vulnerabilities',
    label: 'Vulnerabilities',
    icon: ShieldAlert,
    description: 'Known-exploited CVEs possibly affecting reported software versions.',
    milestone: 'Milestone 13',
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
    milestone: 'Milestone 7',
  },
  {
    path: '/advisories',
    label: 'Advisories',
    icon: FileText,
    description: 'Remediation advisories derived from findings and evidence.',
    milestone: 'Milestone 7',
  },
  {
    path: '/attack-surface',
    label: 'Attack Surface',
    icon: Boxes,
    description:
      'Where assets are hosted and located, what they run, and which services are exposed.',
    milestone: 'Milestone 13',
  },
  {
    path: '/lookalikes',
    label: 'Lookalike domains',
    icon: ScanSearch,
    description: 'Registered look-alikes of your domains (typos, homoglyphs, other TLDs).',
    milestone: 'Milestone 15',
  },
  {
    path: '/changes',
    label: 'Changes',
    icon: History,
    description: 'What changed between successful scans, per host and domain.',
    milestone: 'Milestone 14',
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
