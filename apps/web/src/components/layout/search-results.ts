import type { SearchResponse, Severity } from '@exdomainvault/shared';

export interface SearchItem {
  key: string;
  label: string;
  detail: string | null;
  to: string;
  severity?: Severity;
}

export interface SearchGroup {
  id: string;
  label: string;
  items: SearchItem[];
}

const q = (v: string) => `?q=${encodeURIComponent(v)}`;

/** The search response as display groups (empty groups dropped), each item with its link. */
export function toSearchGroups(res: SearchResponse): SearchGroup[] {
  const groups: SearchGroup[] = [
    {
      id: 'domains',
      label: 'Domains',
      items: res.domains.map((d) => ({
        key: `domain:${d.id}`,
        label: d.fqdn,
        detail: null,
        to: `/domains/${d.id}`,
      })),
    },
    {
      id: 'assets',
      label: 'Subdomains / hosts',
      items: res.assets.map((a) => ({
        key: `asset:${a.id}`,
        label: a.hostname,
        detail: a.domain.fqdn,
        to: `/assets/${a.id}`,
      })),
    },
    {
      id: 'ips',
      label: 'IP addresses',
      items: res.ips.map((ip) => {
        const first = ip.assets[0];
        return {
          key: `ip:${ip.ipAddress}`,
          label: ip.ipAddress,
          detail: ip.assets.map((a) => a.hostname).join(', ') || null,
          to: first ? `/assets/${first.id}` : `/assets${q(ip.ipAddress)}`,
        };
      }),
    },
    {
      id: 'ports',
      label: 'Open ports',
      items: res.ports.map((p) => ({
        key: `port:${p.ipAddress}:${p.port}`,
        label: `${p.ipAddress}:${p.port}`,
        detail: [p.service, p.hostname].filter(Boolean).join(' · ') || null,
        to: `/ports${q(p.ipAddress)}`,
      })),
    },
    {
      id: 'software',
      label: 'Software',
      items: res.software.map((s, i) => ({
        key: `software:${s.product}:${s.version ?? ''}:${s.hostname ?? s.domain.id}:${i}`,
        label: s.version ? `${s.productLabel} ${s.version}` : s.productLabel,
        detail: s.hostname ?? s.domain.fqdn,
        to: `/software${q(s.product)}`,
      })),
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      items: res.vulnerabilities.map((v) => ({
        key: `cve:${v.cve}`,
        label: v.cve,
        detail: [
          v.kev ? 'Known exploited' : null,
          `${v.affectedHosts} ${v.affectedHosts === 1 ? 'host' : 'hosts'} possibly affected`,
        ]
          .filter(Boolean)
          .join(' · '),
        to: `/vulnerabilities${q(v.cve)}`,
      })),
    },
    {
      id: 'findings',
      label: 'Findings',
      items: res.findings.map((f) => ({
        key: `finding:${f.id}`,
        label: f.title,
        detail: f.domain.fqdn,
        to: `/findings/${f.id}`,
        severity: f.severity,
      })),
    },
  ];
  return groups.filter((g) => g.items.length > 0);
}
