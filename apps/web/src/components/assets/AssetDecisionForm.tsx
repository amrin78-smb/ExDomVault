import { useId, useState, type FormEvent, type ReactNode } from 'react';
import { Button } from '../ui/Button.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import {
  ASSET_ACTION_HELP,
  decisionErrorTitle,
  thirdPartyAcknowledgement,
  type AssetAction,
} from './labels.ts';

const REASON_MIN = 3;
const REASON_MAX = 1000;

export interface AssetDecisionValues {
  reason: string;
  acknowledgeThirdPartyHosting: boolean;
}

/**
 * Confirmation form for an asset decision: a required reason and, when approving hostnames that a
 * third-party provider serves, an explicit acknowledgement of what approval allows.
 */
export function AssetDecisionForm({
  action,
  title,
  confirmLabel,
  providers,
  description,
  error,
  errorActions,
  onSubmit,
  onCancel,
}: {
  action: AssetAction;
  title: string;
  confirmLabel: string;
  /** Hosting providers of the affected assets. Non-empty + approve = acknowledgement required. */
  providers: readonly string[];
  description?: ReactNode;
  error?: Error | null;
  errorActions?: ReactNode;
  onSubmit: (values: AssetDecisionValues) => Promise<void>;
  onCancel: () => void;
}) {
  const id = useId();
  const [reason, setReason] = useState('');
  const [ack, setAck] = useState(false);
  const [reasonError, setReasonError] = useState<string | null>(null);
  const [ackError, setAckError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const needsAck = action === 'approve' && providers.length > 0;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const text = reason.trim();
    const rErr =
      text.length === 0
        ? 'A reason is required.'
        : text.length < REASON_MIN
          ? `Enter at least ${REASON_MIN} characters.`
          : null;
    const aErr =
      needsAck && !ack ? 'Confirm the third-party hosting acknowledgement to approve.' : null;
    setReasonError(rErr);
    setAckError(aErr);
    if (rErr || aErr) return;

    setBusy(true);
    try {
      await onSubmit({ reason: text, acknowledgeThirdPartyHosting: needsAck && ack });
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
      <p className="text-fg-muted">{ASSET_ACTION_HELP[action]}</p>
      {description && <div className="text-fg-muted">{description}</div>}
      <div>
        <label htmlFor={`${id}-reason`} className="block font-medium text-fg-2">
          Reason{' '}
          <span className="font-normal text-fg-subtle">
            (required, at least {REASON_MIN} characters; recorded in the audit log)
          </span>
        </label>
        <textarea
          id={`${id}-reason`}
          className="mt-1 w-full rounded-md border border-line-strong px-2.5 py-1.5 text-sm shadow-sm"
          rows={3}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          maxLength={REASON_MAX}
          aria-required
          aria-invalid={reasonError ? true : undefined}
          aria-describedby={reasonError ? `${id}-reason-error` : undefined}
        />
        {reasonError && (
          <p id={`${id}-reason-error`} className="mt-1 text-red-700">
            {reasonError}
          </p>
        )}
      </div>
      {needsAck && (
        <div className="rounded-md border border-violet-200 bg-violet-50 p-2.5">
          <label className="flex gap-2 text-violet-950">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={ack}
              onChange={(e) => setAck(e.target.checked)}
              aria-invalid={ackError ? true : undefined}
              aria-describedby={ackError ? `${id}-ack-error` : undefined}
            />
            <span>{thirdPartyAcknowledgement(providers)}</span>
          </label>
          {ackError && (
            <p id={`${id}-ack-error`} className="mt-1 text-red-700">
              {ackError}
            </p>
          )}
        </div>
      )}
      {error && (
        <div className="space-y-2">
          <ErrorAlert error={error} title={decisionErrorTitle(error)} />
          {errorActions}
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant={action === 'approve' ? 'primary' : 'danger'} disabled={busy}>
          {confirmLabel}
        </Button>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
