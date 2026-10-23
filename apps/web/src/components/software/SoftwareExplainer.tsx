import { Info } from 'lucide-react';

/** How to read software versions and vulnerability matches (shown on the Software page). */
export function SoftwareExplainer() {
  return (
    <div
      role="note"
      aria-label="How to read this inventory"
      className="flex gap-2 rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sm text-sky-900"
    >
      <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div>
        <p className="font-medium">How to read this inventory</p>
        <ul className="mt-1 list-disc space-y-0.5 pl-4">
          <li>
            Versions are <strong>self-reported</strong> by the servers (HTTP headers and service
            banners). They are evidence to verify, not proof.
          </li>
          <li>
            Distributions such as Ubuntu, Debian and Red Hat Enterprise Linux often{' '}
            <strong>backport security fixes</strong> without changing the version number, so an old
            version string may already be patched.
          </li>
          <li>
            A <strong>hidden version</strong> means unknown, not safe.
          </li>
          <li>
            End-of-life and known-exploited (CISA KEV) matches mean{' '}
            <strong>possibly affected — verify</strong> with the system owner or package manager.
          </li>
          <li>
            HTTP server and TLS data need a <strong>Quick</strong> scan or higher; service versions
            on other ports need a <strong>Standard</strong> or <strong>Deep</strong> scan.
          </li>
        </ul>
      </div>
    </div>
  );
}
