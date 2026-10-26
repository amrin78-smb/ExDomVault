/** Display helpers for ISO 3166-1 alpha-2 codes (kept outside the lazily loaded map chunk). */

let regionNames: Intl.DisplayNames | null | undefined;

/** English country name ("DE" → "Germany"); the code itself when the runtime has no name. */
export function countryName(code: string): string {
  if (regionNames === undefined) {
    try {
      regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
    } catch {
      regionNames = null;
    }
  }
  try {
    return regionNames?.of(code) ?? code;
  } catch {
    return code;
  }
}

/** Regional-indicator flag emoji for a two-letter code; empty for anything else. */
export function flagEmoji(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return '';
  return String.fromCodePoint(...[...code].map((c) => 0x1f1a5 + c.charCodeAt(0)));
}
