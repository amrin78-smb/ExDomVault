// The alpha-2 → numeric table is complete, and every country the continent table (and therefore
// the attack-surface API) can return is placeable on the map.
import { COUNTRY_CONTINENT } from '@exdomainvault/shared';
import { feature } from 'topojson-client';
import type { GeometryCollection } from 'topojson-specification';
import topology from 'world-atlas/countries-110m.json';
import { describe, expect, it } from 'vitest';
import {
  ALPHA2_TO_NUMERIC,
  POINT_OVERRIDES,
  SMALL_COUNTRY_POINTS,
  alpha2OfFeature,
} from './country-codes.ts';
import { countryName, flagEmoji } from './country-names.ts';

const features = feature(
  topology,
  topology.objects.countries as GeometryCollection<{ name: string }>,
).features;
const atlasCodes = new Set(features.map((f) => alpha2OfFeature(f.id, f.properties.name)));

describe('ISO 3166-1 mapping', () => {
  it('has all 249 assigned alpha-2 codes with unique three-digit numeric codes', () => {
    const entries = Object.entries(ALPHA2_TO_NUMERIC);
    expect(entries).toHaveLength(249);
    for (const [a, n] of entries) {
      expect(a).toMatch(/^[A-Z]{2}$/);
      expect(n).toMatch(/^\d{3}$/);
    }
    expect(new Set(entries.map(([, n]) => n)).size).toBe(249);
    expect(ALPHA2_TO_NUMERIC.US).toBe('840');
    expect(ALPHA2_TO_NUMERIC.DE).toBe('276');
    expect(ALPHA2_TO_NUMERIC.GB).toBe('826');
  });

  it('maps every world-atlas shape to a code (Kosovo by name)', () => {
    // Only the two shapes without any ISO code stay unmatched (drawn, never shaded).
    expect(
      features
        .filter((f) => !alpha2OfFeature(f.id, f.properties.name))
        .map((f) => f.properties.name),
    ).toEqual(['N. Cyprus', 'Somaliland']);
    expect(atlasCodes.has('XK')).toBe(true);
    expect(alpha2OfFeature('840')).toBe('US');
    expect(alpha2OfFeature(36)).toBe('AU');
  });

  it('places every country the continent table knows: a shape or a fallback point', () => {
    expect(COUNTRY_CONTINENT.size).toBe(250);
    const unplaced = [...COUNTRY_CONTINENT.keys()].filter(
      (code) => !atlasCodes.has(code) && !SMALL_COUNTRY_POINTS[code],
    );
    expect(unplaced).toEqual([]);
    for (const code of COUNTRY_CONTINENT.keys()) {
      if (code !== 'XK') expect(ALPHA2_TO_NUMERIC[code], code).toBeDefined();
    }
  });

  it('keeps fallback and override points on the globe and only for real codes', () => {
    for (const [code, [lon, lat]] of Object.entries({
      ...SMALL_COUNTRY_POINTS,
      ...POINT_OVERRIDES,
    })) {
      expect(ALPHA2_TO_NUMERIC[code], code).toBeDefined();
      expect(Math.abs(lon)).toBeLessThanOrEqual(180);
      expect(Math.abs(lat)).toBeLessThanOrEqual(90);
    }
  });
});

describe('country display helpers', () => {
  it('names countries and builds flag emoji', () => {
    expect(countryName('DE')).toBe('Germany');
    expect(flagEmoji('DE')).toBe('🇩🇪');
    expect(flagEmoji('de')).toBe('');
  });
});
