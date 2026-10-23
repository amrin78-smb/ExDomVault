import { Link } from 'react-router';

/** A short pointer to Settings → Scan profiles, shown where the UI suggests running scans by hand. */
export function ScheduledScansHint() {
  return (
    <span className="mt-1 block">
      Scheduled scans can be enabled in{' '}
      <Link to="/settings?tab=profiles" className="text-sky-800 hover:underline">
        Settings → Scan profiles
      </Link>
      .
    </span>
  );
}
