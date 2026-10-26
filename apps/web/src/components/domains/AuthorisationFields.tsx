import { ATTESTATION_MAX_MONTHS, type AuthorisationInput } from '@exdomainvault/shared';
import { addMonthsIso } from '../../lib/format.ts';

const inputClass = 'w-full rounded-md border border-line-strong px-2.5 py-1.5 text-sm shadow-sm';

/** Reason, reference and review date for an administrator authorisation (controlled). */
export function AuthorisationFields({
  value,
  onChange,
}: {
  value: AuthorisationInput;
  onChange: (next: AuthorisationInput) => void;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <label className="block text-sm font-medium text-fg-2 sm:col-span-3">
        Reason
        <textarea
          className={`${inputClass} mt-1`}
          rows={2}
          value={value.reason}
          onChange={(e) => onChange({ ...value, reason: e.target.value })}
          minLength={10}
          maxLength={500}
          required
          placeholder="e.g. Registered and owned by Thai Union Group; DNS managed by the registrar (CSC)"
        />
      </label>
      <label className="block text-sm font-medium text-fg-2 sm:col-span-2">
        Reference <span className="font-normal text-fg-subtle">(optional: ticket, contract)</span>
        <input
          className={`${inputClass} mt-1`}
          value={value.reference ?? ''}
          onChange={(e) => onChange({ ...value, reference: e.target.value })}
          maxLength={200}
        />
      </label>
      <label className="block text-sm font-medium text-fg-2">
        Review by
        <input
          type="date"
          className={`${inputClass} mt-1`}
          value={value.reviewBy}
          min={addMonthsIso(0, 1)}
          max={addMonthsIso(ATTESTATION_MAX_MONTHS)}
          onChange={(e) => onChange({ ...value, reviewBy: e.target.value })}
          required
        />
      </label>
    </div>
  );
}
