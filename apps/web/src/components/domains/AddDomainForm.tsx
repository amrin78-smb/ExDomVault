import { CRITICALITIES, CRITICALITY_LABELS, type Criticality } from '@exdomainvault/shared';
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { api } from '../../lib/api.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const inputClass = 'w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm';

/** Registers a domain. The server normalises and validates the name; it is not trusted here. */
export function AddDomainForm({ onCancel }: { onCancel: () => void }) {
  const navigate = useNavigate();
  const [fqdn, setFqdn] = useState('');
  const [criticality, setCriticality] = useState<Criticality>('medium');
  const [businessOwner, setBusinessOwner] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const { domain } = await api.domains.create({ fqdn, criticality, businessOwner });
      void navigate(`/domains/${domain.id}`);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      setSubmitting(false);
    }
  };

  return (
    <Card title="Add a domain">
      <form onSubmit={onSubmit} className="space-y-4">
        <p className="text-sm text-slate-600">
          Enter a registered domain you control, such as{' '}
          <code className="font-mono">example.com</code>. Subdomains are tracked as assets of their
          domain. Adding a domain does not authorise any scanning: it must be verified first.
        </p>
        <div className="grid gap-4 sm:grid-cols-3">
          <label className="block text-sm font-medium text-slate-700">
            Domain
            <input
              className={`${inputClass} mt-1 font-mono`}
              value={fqdn}
              onChange={(e) => setFqdn(e.target.value)}
              required
              maxLength={1024}
              autoComplete="off"
              spellCheck={false}
              placeholder="example.com"
            />
          </label>
          <label className="block text-sm font-medium text-slate-700">
            Criticality
            <select
              className={`${inputClass} mt-1 bg-white`}
              value={criticality}
              onChange={(e) => setCriticality(e.target.value as Criticality)}
            >
              {CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {CRITICALITY_LABELS[c]}
                </option>
              ))}
            </select>
          </label>
          <label className="block text-sm font-medium text-slate-700">
            Business owner <span className="font-normal text-slate-500">(optional)</span>
            <input
              className={`${inputClass} mt-1`}
              value={businessOwner}
              onChange={(e) => setBusinessOwner(e.target.value)}
              maxLength={200}
            />
          </label>
        </div>
        {error && <ErrorAlert error={error} title="The domain was not added" />}
        <div className="flex gap-2">
          <Button type="submit" variant="primary" disabled={submitting || fqdn.trim() === ''}>
            {submitting ? 'Adding…' : 'Add domain'}
          </Button>
          <Button onClick={onCancel} disabled={submitting}>
            Cancel
          </Button>
        </div>
      </form>
    </Card>
  );
}
