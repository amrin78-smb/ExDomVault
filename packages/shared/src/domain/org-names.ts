/**
 * Organisation-name matching for network ownership (Milestone 15). Mirrors the worker's
 * `app.network_checks.org_name_matches` exactly; the server re-checks every network observation
 * with this function against the current `discovery_org_names` setting.
 *
 * Both sides are normalised (NFKC, case-folded, every run of non-alphanumeric characters → one
 * space). A configured name matches when, with its spaces removed, it equals a run of consecutive
 * words of the candidate joined together: `Thai Union` matches `Thai Union Group PCL`,
 * `THAI-UNION Europe B.V.` and `THAIUNION-TH`, but not `Thai Unionist`, `Thailand Union` or
 * `THAIUNIONGROUP` (never a substring inside a word).
 */

export function normaliseOrgName(text: string): string {
  return text
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^0-9a-z]+/g, ' ')
    .trim();
}

function tokenRunsEqual(tokens: readonly string[], needle: string): boolean {
  for (let start = 0; start < tokens.length; start++) {
    let joined = '';
    for (let i = start; i < tokens.length; i++) {
      joined += tokens[i];
      if (joined === needle) return true;
      if (joined.length >= needle.length) break;
    }
  }
  return false;
}

export function orgNameMatches(
  orgNames: readonly string[],
  candidates: readonly (string | null | undefined)[],
): boolean {
  const needles = orgNames.map((n) => normaliseOrgName(n).replaceAll(' ', '')).filter(Boolean);
  if (needles.length === 0) return false;
  for (const raw of candidates) {
    if (typeof raw !== 'string' || raw.trim() === '') continue;
    const tokens = normaliseOrgName(raw).split(' ').filter(Boolean);
    if (needles.some((n) => tokenRunsEqual(tokens, n))) return true;
  }
  return false;
}
