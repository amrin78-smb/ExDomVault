import { formatDateTime } from '../../lib/format.ts';
import { formatRelative } from './format.ts';

/** A relative time ("3 days ago") with the absolute UTC time as tooltip and machine value. */
export function RelativeTime({ iso }: { iso: string }) {
  const absolute = formatDateTime(iso);
  return (
    <time dateTime={iso} title={absolute} className="whitespace-nowrap">
      {formatRelative(iso)}
      <span className="sr-only"> ({absolute})</span>
    </time>
  );
}
