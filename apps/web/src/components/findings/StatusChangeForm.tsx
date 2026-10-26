import {
  ACCEPTED_RISK_MAX_DAYS,
  FINDING_REASON_MAX,
  type TransitionRequirements,
} from '@exdomainvault/shared';
import { useId, useState, type FormEvent, type ReactNode } from 'react';
import { Button } from '../ui/Button.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { reviewDateBounds } from './lifecycle.ts';

const inputClass = 'w-full rounded-md border border-line-strong px-2.5 py-1.5 text-sm shadow-sm';

export interface StatusChangeValues {
  reason?: string;
  /** ISO date-time (start of the chosen UTC day). */
  acceptedRiskReviewAt?: string;
}

/**
 * Inline confirmation form for a status change: shows exactly the fields the transition requires
 * (reason required or optional, review date for accepted risk), validates them, and submits.
 */
export function StatusChangeForm({
  title,
  confirmLabel,
  requirements,
  description,
  error,
  onSubmit,
  onCancel,
}: {
  title: string;
  confirmLabel: string;
  requirements: TransitionRequirements;
  description?: ReactNode;
  error?: Error | null;
  onSubmit: (values: StatusChangeValues) => Promise<void>;
  onCancel: () => void;
}) {
  const id = useId();
  const [bounds] = useState(() => reviewDateBounds());
  const [reason, setReason] = useState('');
  const [reviewDate, setReviewDate] = useState(bounds.default);
  const [reasonError, setReasonError] = useState<string | null>(null);
  const [dateError, setDateError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const required = requirements.reason === 'required';

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const text = reason.trim();
    let rErr: string | null = null;
    let dErr: string | null = null;
    if (required && text.length === 0) rErr = 'A reason is required.';
    else if (text.length > 0 && text.length < requirements.reasonMin)
      rErr = `Enter at least ${requirements.reasonMin} characters.`;
    if (requirements.reviewDate) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(reviewDate)) dErr = 'Choose a review date.';
      else if (reviewDate < bounds.min) dErr = 'The review date must be in the future.';
      else if (reviewDate > bounds.max)
        dErr = `The review date must be within ${ACCEPTED_RISK_MAX_DAYS} days.`;
    }
    setReasonError(rErr);
    setDateError(dErr);
    if (rErr || dErr) return;

    setBusy(true);
    try {
      await onSubmit({
        ...(text ? { reason: text } : {}),
        ...(requirements.reviewDate ? { acceptedRiskReviewAt: `${reviewDate}T00:00:00.000Z` } : {}),
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={submit}
      noValidate
      aria-labelledby={`${id}-title`}
      className="space-y-3 rounded-md border border-line bg-surface-2 p-3 text-sm"
    >
      <h3 id={`${id}-title`} className="font-semibold text-fg">
        {title}
      </h3>
      {description && <div className="text-fg-muted">{description}</div>}
      <div>
        <label htmlFor={`${id}-reason`} className="block font-medium text-fg-2">
          Reason{' '}
          <span className="font-normal text-fg-subtle">
            {required ? `(required, at least ${requirements.reasonMin} characters)` : '(optional)'}
          </span>
        </label>
        <textarea
          id={`${id}-reason`}
          className={`${inputClass} mt-1`}
          rows={3}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          maxLength={FINDING_REASON_MAX}
          aria-required={required}
          aria-invalid={reasonError ? true : undefined}
          aria-describedby={reasonError ? `${id}-reason-error` : undefined}
        />
        {reasonError && (
          <p id={`${id}-reason-error`} className="mt-1 text-red-700">
            {reasonError}
          </p>
        )}
      </div>
      {requirements.reviewDate && (
        <div>
          <label htmlFor={`${id}-review`} className="block font-medium text-fg-2">
            Review date{' '}
            <span className="font-normal text-fg-subtle">
              (the finding reopens on this date unless accepted again)
            </span>
          </label>
          <input
            id={`${id}-review`}
            type="date"
            className={`${inputClass} mt-1 sm:w-48`}
            value={reviewDate}
            min={bounds.min}
            max={bounds.max}
            onChange={(e) => setReviewDate(e.target.value)}
            aria-required
            aria-invalid={dateError ? true : undefined}
            aria-describedby={dateError ? `${id}-review-error` : undefined}
          />
          {dateError && (
            <p id={`${id}-review-error`} className="mt-1 text-red-700">
              {dateError}
            </p>
          )}
        </div>
      )}
      {error && <ErrorAlert error={error} title="The change was not saved" />}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" disabled={busy}>
          {confirmLabel}
        </Button>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
