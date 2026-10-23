import type { SoftwareSummaryResponse } from '@exdomainvault/shared';
import { Link } from 'react-router';

type Product = SoftwareSummaryResponse['products'][number];

const MAX_VERSIONS = 4;

/** A proportional bar; decorative only — the number is always shown as text beside it. */
function Bar({ value, max, className }: { value: number; max: number; className: string }) {
  const pct = max > 0 ? Math.max(value > 0 ? 4 : 0, Math.round((value / max) * 100)) : 0;
  return (
    <div className="h-1.5 w-24 rounded-full bg-slate-100" aria-hidden>
      <div className={`h-1.5 rounded-full ${className}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

function Versions({ versions }: { versions: Product['versions'] }) {
  const sorted = [...versions].sort((a, b) => b.hosts - a.hosts);
  const shown = sorted.slice(0, MAX_VERSIONS);
  const rest = sorted.slice(MAX_VERSIONS).reduce((n, v) => n + v.hosts, 0);
  return (
    <ul className="flex flex-wrap gap-1 text-xs">
      {shown.map((v) => (
        <li
          key={v.version ?? '(hidden)'}
          className="whitespace-nowrap rounded bg-slate-100 px-1.5 py-0.5 text-slate-700"
        >
          {v.version === null ? (
            <span className="italic">hidden</span>
          ) : (
            <span className="font-mono">{v.version}</span>
          )}{' '}
          × {v.hosts}
        </li>
      ))}
      {rest > 0 && (
        <li className="whitespace-nowrap px-1.5 py-0.5 text-slate-500">
          + {rest} on other versions
        </li>
      )}
    </ul>
  );
}

/** Portfolio rollup per product: hosts, version distribution, end-of-life and possible KEV. */
export function SoftwareRollup({
  products,
  productHref,
}: {
  products: Product[];
  productHref: (product: string) => string;
}) {
  const max = Math.max(0, ...products.map((p) => p.hosts));
  const sorted = [...products].sort(
    (a, b) => b.knownExploited - a.knownExploited || b.eol - a.eol || b.hosts - a.hosts,
  );
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
            <th scope="col" className="py-2 pr-4">
              Product
            </th>
            <th scope="col" className="py-2 pr-4">
              Hosts
            </th>
            <th scope="col" className="py-2 pr-4">
              Versions
            </th>
            <th scope="col" className="py-2 pr-4">
              End of life
            </th>
            <th scope="col" className="py-2">
              Possibly KEV-affected
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {sorted.map((p) => (
            <tr key={p.product}>
              <td className="whitespace-nowrap py-2 pr-4 align-top">
                <Link to={productHref(p.product)} className="text-sky-800 hover:underline">
                  {p.productLabel}
                </Link>
              </td>
              <td className="py-2 pr-4 align-top">
                <div className="flex items-center gap-2">
                  <span className="w-8 text-right tabular-nums text-slate-800">{p.hosts}</span>
                  <Bar value={p.hosts} max={max} className="bg-slate-500" />
                </div>
              </td>
              <td className="py-2 pr-4 align-top">
                <Versions versions={p.versions} />
              </td>
              <td className="py-2 pr-4 align-top">
                <div className="flex items-center gap-2">
                  <span className="w-8 text-right tabular-nums text-slate-800">{p.eol}</span>
                  <Bar value={p.eol} max={p.hosts} className="bg-amber-500" />
                </div>
              </td>
              <td className="py-2 align-top">
                <div className="flex items-center gap-2">
                  <span className="w-8 text-right tabular-nums text-slate-800">
                    {p.knownExploited}
                  </span>
                  <Bar value={p.knownExploited} max={p.hosts} className="bg-orange-600" />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
