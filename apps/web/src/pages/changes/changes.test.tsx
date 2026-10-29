// Change timeline (Milestone 14): the /changes page, the asset/domain Changes cards and the
// Overview "Recent changes" card.
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { dayLabel, diffLines, linesOf } from '../../components/changes/format.ts';
import {
  CHANGE_ASSET_ID,
  CHANGE_DOMAIN_ID,
  RECENT_CHANGES_PATH,
  changeEvent,
  changesPage,
  changesPath,
} from '../../components/changes/test-data.ts';
import { toQuery } from '../../lib/api.ts';
import { ASSET_PATHS, apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { ASSET_ID, detailOf } from '../assets/test-data.ts';
import { domain, page } from '../findings/test-data.ts';

beforeEach(() => localStorage.clear());
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const dnsChange = changeEvent();
const portChange = changeEvent({
  id: 'port:job-9:192.0.2.20:8443/tcp',
  at: '2026-10-22T09:30:00.000Z',
  kind: 'port',
  hostname: null,
  subject: '192.0.2.20 8443/tcp',
  summary: 'Port 192.0.2.20 8443/tcp opened (was closed)',
  before: { state: 'closed' },
  after: { state: 'open' },
  severityHint: 'important',
});
const assetChange = changeEvent({
  id: 'asset:x:discovered',
  at: '2026-10-20T07:00:00.000Z',
  kind: 'asset',
  hostname: 'new.example.com',
  assetId: null,
  subject: 'asset',
  summary: 'New asset new.example.com added (source: dns)',
  before: null,
  after: { source: 'dns' },
  severityHint: 'info',
});
const ALL_ITEMS = [portChange, dnsChange, assetChange];

describe('diff helpers', () => {
  it('turns values into lines and diffs them as sets', () => {
    expect(linesOf(null)).toEqual([]);
    expect(linesOf(['a', 'b'])).toEqual(['a', 'b']);
    expect(linesOf({ issuer: ['X', 'Y'], protocols: [], state: 'open', hsts: true })).toEqual([
      'issuer: X',
      'issuer: Y',
      'protocols: —',
      'state: open',
      'hsts: true',
    ]);
    expect(diffLines(['a', 'b'], ['b', 'c'])).toEqual([
      { op: 'same', text: 'b' },
      { op: 'removed', text: 'a' },
      { op: 'added', text: 'c' },
    ]);
  });
});

describe('Changes page', () => {
  it('is reachable from the navigation and groups events by day with importance chips', async () => {
    stubApi('viewer', {
      [changesPath()]: ok(changesPage(ALL_ITEMS)),
      'GET /api/v1/domains?pageSize=100': ok(page([domain()])),
    });
    renderAt('/');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    await userEvent.click(within(nav).getByRole('link', { name: 'Changes' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Changes' })).toBeInTheDocument();

    const oct22 = await screen.findByRole('region', { name: dayLabel(dnsChange.at) });
    expect(within(oct22).getByText(portChange.summary)).toBeInTheDocument();
    expect(within(oct22).getByText(dnsChange.summary)).toBeInTheDocument();
    const oct20 = screen.getByRole('region', { name: dayLabel(assetChange.at) });
    expect(within(oct20).getByText(assetChange.summary)).toBeInTheDocument();

    // Newest first within a day; chips carry text, not just colour.
    const items = within(oct22).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent(portChange.summary);
    expect(within(items[0]!).getByText('Important')).toHaveAttribute(
      'data-importance',
      'important',
    );
    expect(within(items[1]!).getByText('Notable')).toBeInTheDocument();
    expect(within(oct20).getByText('Info')).toBeInTheDocument();
    expect(screen.getByText('3 changes in 30 days · 1 important · 1 notable')).toBeInTheDocument();

    // Links to the asset and domain.
    expect(within(items[1]!).getByRole('link', { name: 'www.example.com' })).toHaveAttribute(
      'href',
      `/assets/${CHANGE_ASSET_ID}`,
    );
    expect(within(items[1]!).getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/domains/${CHANGE_DOMAIN_ID}`,
    );
    // No asset id: the hostname is plain text.
    expect(within(oct20).queryByRole('link', { name: 'new.example.com' })).toBeNull();
  });

  it('shows a before/after diff on demand', async () => {
    stubApi('viewer', { [changesPath()]: ok(changesPage([dnsChange])) });
    renderAt('/changes');
    const toggle = await screen.findByRole('button', { name: 'Show details' });
    expect(screen.queryByRole('list', { name: 'Differences' })).toBeNull();
    await userEvent.click(toggle);
    const diff = screen.getByRole('list', { name: 'Differences' });
    const lines = within(diff).getAllByRole('listitem');
    expect(lines.map((l) => l.textContent?.replace(/\s+/g, ' ').trim())).toEqual([
      'Unchanged: 192.0.2.2',
      '−Removed: 192.0.2.1',
      '+Added: 192.0.2.3',
    ]);
    expect(lines[1]!.className).toMatch(/red/);
    expect(lines[2]!.className).toMatch(/emerald/);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
  });

  it('sends the kind, importance and period filters and keeps them in the URL', async () => {
    const now = Date.parse('2026-10-23T10:00:00.000Z');
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const since7 = new Date(now - 7 * 86_400_000).toISOString();
    const calls = stubApi('analyst', {
      [changesPath()]: ok(changesPage(ALL_ITEMS)),
      [changesPath('?kind=port')]: ok(changesPage([portChange])),
      [changesPath('?kind=port&importance=important')]: ok(changesPage([portChange])),
      [changesPath(toQuery({ kind: 'port', importance: 'important', since: since7 }))]: ok(
        changesPage([portChange]),
      ),
      [changesPath(
        toQuery({
          kind: 'port',
          importance: 'important',
          since: '2026-10-01T00:00:00.000Z',
          until: '2026-10-03T00:00:00.000Z',
        }),
      )]: ok(changesPage([])),
    });
    const router = renderAt('/changes');
    await screen.findByText(dnsChange.summary);
    await userEvent.selectOptions(screen.getByLabelText('Kind'), 'port');
    await waitFor(() => expect(screen.queryByText(dnsChange.summary)).toBeNull());
    await userEvent.selectOptions(screen.getByLabelText('Importance'), 'important');
    await userEvent.selectOptions(screen.getByLabelText('Period'), '7');
    await waitFor(() =>
      expect(calls.some((c) => c.path.includes(encodeURIComponent(since7)))).toBe(true),
    );
    expect(router.state.location.search).toBe('?kind=port&importance=important&days=7');

    await userEvent.selectOptions(screen.getByLabelText('Period'), 'custom');
    await userEvent.type(screen.getByLabelText('From'), '2026-10-01');
    await userEvent.type(screen.getByLabelText('To'), '2026-10-02');
    expect(await screen.findByText('No changes match these filters')).toBeInTheDocument();
  });

  it('shows the asset filter as a removable chip', async () => {
    stubApi('viewer', {
      [changesPath(`?assetId=${CHANGE_ASSET_ID}`)]: ok(changesPage([dnsChange])),
      [changesPath()]: ok(changesPage(ALL_ITEMS)),
    });
    const router = renderAt(`/changes?assetId=${CHANGE_ASSET_ID}`);
    const chip = await screen.findByRole('button', { name: /Asset: www.example.com/ });
    await userEvent.click(chip);
    expect(router.state.location.search).toBe('');
    expect(await screen.findByText(assetChange.summary)).toBeInTheDocument();
  });

  it('has empty and error states', async () => {
    stubApi('viewer', { [changesPath()]: ok(changesPage([])) });
    renderAt('/changes');
    expect(await screen.findByText('No changes in this period')).toBeInTheDocument();
    vi.unstubAllGlobals();

    stubApi('viewer', {
      [changesPath()]: apiError(500, 'internal_error', 'Something went wrong.'),
    });
    renderAt('/changes');
    expect(await screen.findByText('Could not load changes')).toBeInTheDocument();
  });
});

describe('Changes cards', () => {
  it('summarises an asset’s changes while collapsed and lists them when opened', async () => {
    stubApi('viewer', {
      [ASSET_PATHS.detail(ASSET_ID)]: ok(detailOf()),
      [changesPath(`?assetId=${ASSET_ID}&pageSize=20`)]: ok(
        changesPage([portChange, dnsChange], { total: 25, pageSize: 20 }),
      ),
    });
    renderAt(`/assets/${ASSET_ID}`);
    const card = await screen.findByRole('region', { name: 'Changes' });
    const header = within(card).getByRole('button', { name: /Changes/ });
    expect(header).toHaveAttribute('aria-expanded', 'false');
    expect(
      await within(card).findByText('25 changes in 30 days · 1 important'),
    ).toBeInTheDocument();
    await userEvent.click(header);
    expect(within(card).getByText(portChange.summary)).toBeVisible();
    expect(within(card).getByRole('link', { name: 'View all 25 changes' })).toHaveAttribute(
      'href',
      `/changes?assetId=${ASSET_ID}`,
    );
    // Inside one domain's context the domain link is not repeated.
    expect(within(card).queryByRole('link', { name: 'example.com' })).toBeNull();
  });

  it('shows an empty domain card with an explanation', async () => {
    stubApi('viewer', {
      [`GET /api/v1/domains/${CHANGE_DOMAIN_ID}`]: ok({
        domain: domain({ id: CHANGE_DOMAIN_ID }),
        verification: null,
      }),
      [changesPath(`?domainId=${CHANGE_DOMAIN_ID}&pageSize=20`)]: ok(changesPage([])),
    });
    renderAt(`/domains/${CHANGE_DOMAIN_ID}`);
    const card = await screen.findByRole('region', { name: 'Changes' });
    expect(await within(card).findByText('No changes in 30 days')).toBeInTheDocument();
    await userEvent.click(within(card).getByRole('button', { name: /Changes/ }));
    expect(within(card).getByText('No changes in the last 30 days')).toBeVisible();
  });
});

describe('Overview: recent changes', () => {
  it('lists notable changes with a link to the full timeline', async () => {
    stubApi('analyst', {
      [RECENT_CHANGES_PATH]: ok(changesPage([portChange, dnsChange])),
    });
    renderAt('/');
    const card = await screen.findByRole('region', { name: 'Recent changes' });
    expect(await within(card).findByText(portChange.summary)).toBeInTheDocument();
    expect(within(card).getByText('Important')).toBeInTheDocument();
    expect(within(card).getByRole('link', { name: /View all/ })).toHaveAttribute(
      'href',
      '/changes?importance=notable',
    );
  });

  it('says so when nothing notable changed', async () => {
    stubApi('analyst', { [RECENT_CHANGES_PATH]: ok(changesPage([])) });
    renderAt('/');
    const card = await screen.findByRole('region', { name: 'Recent changes' });
    expect(await within(card).findByText('No notable changes in 30 days')).toBeInTheDocument();
  });
});
