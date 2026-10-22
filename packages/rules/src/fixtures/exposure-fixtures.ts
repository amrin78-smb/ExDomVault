/** Synthetic port fixtures (test-only). Documentation addresses only. */
import type { PortObservation } from '../types.ts';
import { asPrevious, port } from './builders.ts';

export const IP4 = '203.0.113.10';
export const IP6 = '2001:db8::10';

export function openPort(
  ip: string,
  p: number,
  service: string | null = null,
  evidence: Record<string, unknown> = { method: 'nmap-sT', reason: 'syn-ack' },
): PortObservation {
  return port({ ipAddress: ip, port: p, state: 'open', service }, { evidence });
}

export function portState(
  ip: string,
  p: number,
  state: PortObservation['state'],
  status: PortObservation['resultStatus'] = 'success',
): PortObservation {
  return port(
    { ipAddress: ip, port: p, state, service: null },
    {
      status,
      evidence: { method: 'nmap-sT', reason: state === 'closed' ? 'conn-refused' : 'no-response' },
    },
  );
}

/** Baseline from an earlier successful job. */
export function baseline(items: PortObservation[]): PortObservation[] {
  return asPrevious(items);
}
