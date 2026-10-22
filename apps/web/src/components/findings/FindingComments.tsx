import { FINDING_COMMENT_MAX, type FindingComment } from '@exdomainvault/shared';
import { useId, useState, type FormEvent } from 'react';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { userLabel } from './labels.ts';

/** Remediation notes and discussion on a finding, oldest first. */
export function FindingComments({
  findingId,
  comments,
  canComment,
  onAdded,
}: {
  findingId: string;
  comments: FindingComment[];
  canComment: boolean;
  onAdded: () => Promise<void>;
}) {
  const id = useId();
  const [body, setBody] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [announcement, setAnnouncement] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const text = body.trim();
    if (!text) return;
    setBusy(true);
    setError(null);
    setAnnouncement('');
    try {
      await api.findings.addComment(findingId, text);
      setBody('');
      setAnnouncement('Comment added.');
      await onAdded();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Comments" className="lg:col-span-2">
      {comments.length === 0 ? (
        <p className="text-sm text-slate-500">No comments yet.</p>
      ) : (
        <ol className="space-y-3 text-sm">
          {comments.map((c) => (
            <li key={c.id} className="rounded-md border border-slate-100 px-3 py-2">
              <div className="text-xs text-slate-500">
                <span className="font-medium text-slate-700">
                  {userLabel(c.author, 'Former user')}
                </span>{' '}
                · <time dateTime={c.createdAt}>{formatDateTime(c.createdAt)}</time>
              </div>
              <p className="mt-1 whitespace-pre-wrap break-words text-slate-800">{c.body}</p>
            </li>
          ))}
        </ol>
      )}

      {canComment && (
        <form onSubmit={submit} className="mt-4 space-y-2 text-sm">
          <label htmlFor={`${id}-body`} className="block font-medium text-slate-700">
            Add a comment
          </label>
          <textarea
            id={`${id}-body`}
            className="w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm"
            rows={3}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            maxLength={FINDING_COMMENT_MAX}
            aria-describedby={`${id}-count`}
            placeholder="Remediation notes, context or questions"
          />
          <div className="flex items-center justify-between gap-2">
            <span id={`${id}-count`} className="text-xs text-slate-500">
              {body.length} / {FINDING_COMMENT_MAX} characters
            </span>
            <Button type="submit" variant="primary" disabled={busy || body.trim().length === 0}>
              Add comment
            </Button>
          </div>
          {error && <ErrorAlert error={error} title="The comment was not added" />}
        </form>
      )}
      <p className="sr-only" aria-live="polite">
        {announcement}
      </p>
    </Card>
  );
}
