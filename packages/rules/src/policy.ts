import type { AdministrativeService } from './types.ts';

/**
 * Default exposure policy for EXP-002: administrative and data services that should not be reachable
 * from the internet. An open port alone is an observation; listing it here states the policy that
 * makes it a finding. Exceptions are handled as accepted risk (Milestone 8).
 */
export const DEFAULT_ADMINISTRATIVE_SERVICES: readonly AdministrativeService[] = [
  { port: 21, service: 'FTP', severity: 'medium' },
  { port: 22, service: 'SSH', severity: 'medium' },
  { port: 23, service: 'Telnet', severity: 'high' },
  { port: 111, service: 'RPCbind', severity: 'medium' },
  { port: 135, service: 'Microsoft RPC', severity: 'high' },
  { port: 139, service: 'NetBIOS', severity: 'high' },
  { port: 445, service: 'SMB', severity: 'high' },
  { port: 873, service: 'rsync', severity: 'medium' },
  { port: 1433, service: 'Microsoft SQL Server', severity: 'high' },
  { port: 1521, service: 'Oracle database', severity: 'high' },
  { port: 2049, service: 'NFS', severity: 'high' },
  { port: 2375, service: 'Docker API (plain)', severity: 'critical' },
  { port: 2376, service: 'Docker API (TLS)', severity: 'high' },
  { port: 3306, service: 'MySQL', severity: 'high' },
  { port: 3389, service: 'Remote Desktop (RDP)', severity: 'high' },
  { port: 5432, service: 'PostgreSQL', severity: 'high' },
  { port: 5601, service: 'Kibana', severity: 'medium' },
  { port: 5900, service: 'VNC', severity: 'high' },
  { port: 5984, service: 'CouchDB', severity: 'high' },
  { port: 6379, service: 'Redis', severity: 'high' },
  { port: 6443, service: 'Kubernetes API', severity: 'high' },
  { port: 9200, service: 'Elasticsearch', severity: 'high' },
  { port: 10250, service: 'Kubelet API', severity: 'high' },
  { port: 11211, service: 'Memcached', severity: 'high' },
  { port: 15672, service: 'RabbitMQ management', severity: 'medium' },
  { port: 27017, service: 'MongoDB', severity: 'high' },
];
