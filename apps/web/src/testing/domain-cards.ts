/** Storage keys (after `exdv.card.`) of the collapsible cards on the domain detail page. */
export const DOMAIN_CARD_KEYS = [
  'findings',
  'software',
  'assets',
  'scans',
  'verification',
  'ownership',
  'registration',
  'ports',
  'dns',
  'tls',
  'http',
] as const;

/**
 * Starts the test as a viewer who has opened every domain card, so tests about a card's contents
 * need not click it open first. Call in `beforeEach`.
 */
export function openDomainCards() {
  window.localStorage.clear();
  for (const key of DOMAIN_CARD_KEYS) window.localStorage.setItem(`exdv.card.domain.${key}`, '1');
}
