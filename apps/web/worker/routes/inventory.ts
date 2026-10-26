import {
  certificatesQuerySchema,
  portsQuerySchema,
  vulnerabilitiesQuerySchema,
  type AttackSurfaceResponse,
  type CertificatesResponse,
  type PortsResponse,
  type VulnerabilitiesResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { attackSurface } from '../services/attack-surface.ts';
import { listCertificates, listPorts, listVulnerabilities } from '../services/inventory.ts';
import type { AppBindings } from '../types.ts';

export interface InventoryRouteDeps {
  now?: () => Date;
}

/**
 * Cross-domain inventory views (Milestone 13), each mounted at its own path on the authenticated
 * app: /ports, /certificates, /attack-surface (`assets:read`) and /vulnerabilities (`findings:read`,
 * like /software). Read-only; asset owners see only their assets (enforced in the services).
 */
export function portRoutes() {
  return new Hono<AppBindings>().get('/', requirePermission('assets:read'), async (c) => {
    const query = parseQuery(c, portsQuerySchema);
    const db = await c.get('db')();
    const res: PortsResponse = await listPorts(db, c.get('user'), query);
    return c.json(res);
  });
}

export function certificateRoutes(deps: InventoryRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>().get('/', requirePermission('assets:read'), async (c) => {
    const query = parseQuery(c, certificatesQuerySchema);
    const db = await c.get('db')();
    const res: CertificatesResponse = await listCertificates(db, c.get('user'), query, now());
    return c.json(res);
  });
}

export function vulnerabilityRoutes() {
  return new Hono<AppBindings>().get('/', requirePermission('findings:read'), async (c) => {
    const query = parseQuery(c, vulnerabilitiesQuerySchema);
    const db = await c.get('db')();
    const res: VulnerabilitiesResponse = await listVulnerabilities(db, c.get('user'), query);
    return c.json(res);
  });
}

export function attackSurfaceRoutes(deps: InventoryRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>().get('/', requirePermission('assets:read'), async (c) => {
    const db = await c.get('db')();
    const res: AttackSurfaceResponse = await attackSurface(db, c.get('user'), now());
    return c.json(res);
  });
}
