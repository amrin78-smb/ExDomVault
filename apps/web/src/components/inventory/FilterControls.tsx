import { Search } from 'lucide-react';
import { useState, type FormEvent, type ReactNode } from 'react';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';

export const selectClass =
  'rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-fg-2 shadow-sm';
export const inputClass =
  'rounded-md border border-line-strong bg-surface py-1.5 text-sm text-fg shadow-sm placeholder:text-fg-faint';

/** Free-text search applied on submit (not on every keystroke, so each search is one request). */
export function SearchForm({
  id,
  label,
  placeholder,
  value,
  onSearch,
  children,
}: {
  id: string;
  label: string;
  placeholder: string;
  value: string;
  onSearch: (value: string) => void;
  /** Extra inputs submitted with the search (e.g. a port number). */
  children?: ReactNode;
}) {
  const [draft, setDraft] = useState(value);
  // Follow URL changes made elsewhere (Back, a cleared filter) without an effect round-trip.
  const [seen, setSeen] = useState(value);
  if (seen !== value) {
    setSeen(value);
    setDraft(value);
  }
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSearch(draft.trim());
  };
  return (
    <form onSubmit={submit} role="search" className="flex flex-wrap items-end gap-2">
      <div>
        <label htmlFor={id} className="sr-only">
          {label}
        </label>
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-2 top-2 size-4 text-fg-faint"
            aria-hidden
          />
          <input
            id={id}
            type="search"
            value={draft}
            maxLength={100}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={placeholder}
            className={`${inputClass} w-64 pl-8 pr-2`}
          />
        </div>
      </div>
      {children}
      <Button type="submit">Search</Button>
    </form>
  );
}

export function SelectFilter({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: readonly { value: string; label: string }[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="text-xs text-fg-muted">
      <span className="mb-1 block">{label}</span>
      <select className={selectClass} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

/**
 * Domain filter. The options come from the domain list, which needs `domains:read` (asset owners
 * lack it); without it the select only appears when the URL already names a domain, so the filter
 * can still be cleared.
 */
export function DomainFilter({
  value,
  fallbackLabel,
  onChange,
}: {
  value: string;
  /** Label for a selected domain not in the loaded options (e.g. from the current rows). */
  fallbackLabel?: string;
  onChange: (value: string) => void;
}) {
  const canReadDomains = usePermission('domains:read');
  const domains = useAsync(
    (signal) =>
      canReadDomains
        ? api.domains.list({ pageSize: 100 }, { signal })
        : Promise.resolve({ items: [], page: 1, pageSize: 100, total: 0 }),
    [canReadDomains],
  );
  const options = domains.status === 'success' ? domains.data.items : [];
  if (options.length === 0 && !value) return null;
  return (
    <SelectFilter
      label="Domain"
      value={value}
      onChange={onChange}
      options={[
        { value: '', label: 'All domains' },
        ...(value && !options.some((d) => d.id === value)
          ? [{ value, label: fallbackLabel ?? 'Selected domain' }]
          : []),
        ...options.map((d) => ({ value: d.id, label: d.fqdn })),
      ]}
    />
  );
}
