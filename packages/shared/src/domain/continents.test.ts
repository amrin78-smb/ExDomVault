import { describe, expect, it } from 'vitest';
import { CONTINENTS } from '../api/inventory.ts';
import { COUNTRY_CONTINENT, continentOf } from './continents.ts';

/** Region codes Intl knows that are not current ISO 3166-1 alpha-2 assignments. */
const NOT_CURRENT_ISO = new Set(
  'AC AN BU CP CQ CS DD DG DY EA EU EZ FX HV IC NH QO RH SU TA TP UK UN VD XA XB XK YD YU ZR ZZ'.split(
    ' ',
  ),
);

function intlRegionCodes(): string[] {
  const names = new Intl.DisplayNames(['en'], { type: 'region', fallback: 'none' });
  const out: string[] = [];
  for (let a = 65; a <= 90; a++) {
    for (let b = 65; b <= 90; b++) {
      const code = String.fromCharCode(a, b);
      try {
        if (names.of(code)) out.push(code);
      } catch {
        // not a region code
      }
    }
  }
  return out;
}

describe('COUNTRY_CONTINENT', () => {
  it('maps every current ISO 3166-1 alpha-2 code exactly once (plus XK)', () => {
    const iso = intlRegionCodes().filter((c) => !NOT_CURRENT_ISO.has(c));
    expect(iso).toHaveLength(249);
    for (const code of iso) expect(continentOf(code), code).not.toBeNull();
    expect(COUNTRY_CONTINENT.size).toBe(250);
    expect([...COUNTRY_CONTINENT.keys()].filter((c) => !iso.includes(c))).toEqual(['XK']);
    expect(new Set(COUNTRY_CONTINENT.values())).toEqual(new Set(CONTINENTS));
  });

  it('follows the documented conventions', () => {
    expect(continentOf('RU')).toBe('Europe');
    expect(continentOf('TR')).toBe('Asia');
    expect(continentOf('EG')).toBe('Africa');
    expect(continentOf('PA')).toBe('North America');
    expect(continentOf('AQ')).toBe('Antarctica');
    expect(continentOf('BR')).toBe('South America');
    expect(continentOf('NZ')).toBe('Oceania');
    expect(continentOf('NL')).toBe('Europe');
    expect(continentOf('US')).toBe('North America');
    expect(continentOf('GB')).toBe('Europe');
    expect(continentOf('ZZ')).toBeNull();
    expect(continentOf('nl')).toBeNull();
  });
});
