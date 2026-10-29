/**
 * Dependency-free hostname syntax checks (safe for the SPA bundle; `normalise.ts` carries the PSL).
 * Inputs are expected in canonical form already: lowercase A-labels, no trailing dot.
 */

/** LDH label: 1–63 letters, digits or hyphens, not starting or ending with a hyphen. */
export const LDH_LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
/** Service label such as `_dmarc` or `_tcp`: an underscore, then an LDH label. */
const SERVICE_LABEL_RE = /^_(?!-)[a-z0-9-]{1,62}(?<!-)$/;

/** Service labels that follow a selector label (`selector1._domainkey`, `default._bimi`). */
const SELECTOR_SERVICE_LABELS = new Set(['_domainkey', '_bimi']);

export interface HostnameSyntaxOptions {
  /**
   * Allow leading `_`-prefixed service labels (`_dmarc.example.com`, `_25._tcp.mx.example.com`).
   * Only DNS lookups use such names; nothing ever connects to them. Also allows the selector form
   * `<selector>._domainkey.<domain>` (DKIM) and `<selector>._bimi.<domain>` (BIMI): one LDH label
   * followed by one of those two service labels.
   */
  allowServiceLabels?: boolean;
}

/** True for a syntactically valid multi-label hostname (≤ 253 chars, no empty labels). */
export function isValidHostname(name: string, opts: HostnameSyntaxOptions = {}): boolean {
  if (typeof name !== 'string' || name.length === 0 || name.length > 253) return false;
  const labels = name.split('.');
  if (labels.length < 2) return false;
  let i = 0;
  if (opts.allowServiceLabels) {
    if (
      SELECTOR_SERVICE_LABELS.has(labels[1] as string) &&
      LDH_LABEL_RE.test(labels[0] as string)
    ) {
      i = 2;
    }
    while (i < labels.length && SERVICE_LABEL_RE.test(labels[i] as string)) i++;
  }
  // At least two ordinary labels remain (a service label is never the domain itself).
  if (labels.length - i < 2) return false;
  for (; i < labels.length; i++) if (!LDH_LABEL_RE.test(labels[i] as string)) return false;
  return true;
}

/** True when the name contains an empty label (`.a.b`, `a..b`, `a.b.`). */
export function hasEmptyLabel(name: string): boolean {
  return name.split('.').some((l) => l.length === 0);
}
