import type { ObservationResult } from '@exdomainvault/shared';

/** Plain-language outcome of a check that did not fully succeed. */
export const RESULT_NOTES: Record<Exclude<ObservationResult, 'success'>, string> = {
  partial: 'partial result',
  error: 'lookup failed',
  timeout: 'lookup timed out',
  skipped: 'not checked',
};
