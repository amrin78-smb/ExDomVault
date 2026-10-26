// WorldMap: shading, tooltip, zoom controls and the DB-IP attribution.
import { DBIP_ATTRIBUTION } from '@exdomainvault/shared';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { WorldMap } from './WorldMap.tsx';

const COUNTRIES = [
  { country: 'US', assets: 8, ips: 12 },
  { country: 'DE', assets: 2, ips: 3 },
  { country: 'SG', assets: 1, ips: 1 },
];

const viewport = () => screen.getByTestId('map-viewport');

describe('WorldMap', () => {
  it('labels countries with data and draws a dot for each (small states included)', () => {
    const { container } = render(<WorldMap countries={COUNTRIES} />);
    expect(
      screen.getByRole('img', { name: 'United States: 8 assets, 12 IPs' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Germany: 2 assets, 3 IPs' })).toBeInTheDocument();
    // Singapore has no shape at 110m but still gets a dot (2 circles per dot: halo + core).
    expect(container.querySelectorAll('circle')).toHaveLength(6);
    expect(container.querySelector('path[data-country="FR"]')).toHaveAttribute('aria-hidden');
  });

  it('shows a tooltip with name, assets and IPs on hover and focus', () => {
    render(<WorldMap countries={COUNTRIES} />);
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
    fireEvent.mouseEnter(screen.getByRole('img', { name: /^Germany/ }));
    expect(screen.getByRole('tooltip')).toHaveTextContent('Germany');
    expect(screen.getByRole('tooltip')).toHaveTextContent('2 assets · 3 IPs');
    fireEvent.focus(screen.getByRole('img', { name: /^United States/ }));
    expect(screen.getByRole('tooltip')).toHaveTextContent('United States8 assets · 12 IPs');
  });

  it('zooms in and out about the centre and resets', async () => {
    render(<WorldMap countries={COUNTRIES} />);
    expect(viewport()).toHaveAttribute('transform', 'translate(0 0) scale(1)');
    expect(screen.getByRole('button', { name: 'Zoom out' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
    expect(viewport().getAttribute('transform')).toMatch(/scale\(1\.6\)$/);
    await userEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
    expect(viewport().getAttribute('transform')).toMatch(/scale\(2\.56\)$/);
    await userEvent.click(screen.getByRole('button', { name: 'Zoom out' }));
    expect(viewport().getAttribute('transform')).toMatch(/scale\(1\.6\)$/);
    await userEvent.click(screen.getByRole('button', { name: 'Reset map view' }));
    expect(viewport()).toHaveAttribute('transform', 'translate(0 0) scale(1)');
  });

  it('always shows the DB-IP attribution with a link while data is drawn', () => {
    const { rerender } = render(<WorldMap countries={COUNTRIES} />);
    expect(screen.getByRole('link', { name: DBIP_ATTRIBUTION })).toHaveAttribute(
      'href',
      'https://db-ip.com',
    );
    rerender(<WorldMap countries={COUNTRIES} attribution="" />);
    expect(screen.getByRole('link', { name: DBIP_ATTRIBUTION })).toBeInTheDocument();
    rerender(<WorldMap countries={[]} />);
    expect(screen.queryByRole('link', { name: DBIP_ATTRIBUTION })).not.toBeInTheDocument();
  });

  it('compact mode has no zoom controls', () => {
    render(<WorldMap countries={COUNTRIES} compact height={200} />);
    expect(screen.queryByRole('button', { name: 'Zoom in' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: DBIP_ATTRIBUTION })).toBeInTheDocument();
  });
});
