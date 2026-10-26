import {
  CRITICALITY_LABELS,
  FINDING_STATUS_LABELS,
  SEVERITY_LABELS,
  type FindingDetailResponse,
} from '@exdomainvault/shared';
import { ArrowLeft, Info } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { EvidenceView } from '../../components/findings/EvidenceView.tsx';
import { FindingComments } from '../../components/findings/FindingComments.tsx';
import { FindingStatusBadge } from '../../components/findings/FindingStatusBadge.tsx';
import { FindingWorkflow } from '../../components/findings/FindingWorkflow.tsx';
import {
  CATEGORY_LABELS,
  CONFIDENCE_LABELS,
  EXPOSURE_LABELS,
  historyReasonLabel,
} from '../../components/findings/labels.ts';
import { RiskScore } from '../../components/findings/RiskScore.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { useCollapseAll } from '../../components/ui/CollapseAllControls.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { SeverityBadge } from '../../components/ui/SeverityBadge.tsx';
import { useShowAll } from '../../components/ui/ShowAllButton.tsx';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermissions } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';

export function FindingDetailPage() {
  const { id = '' } = useParams();
  const state = useAsync((signal) => api.findings.get(id, { signal }), [id]);
  // After a change, the latest version replaces the loaded one without unmounting the page (so
  // focus, open forms and result messages survive the reload).
  const [fresh, setFresh] = useState<{ id: string; data: FindingDetailResponse } | null>(null);
  const refresh = async () => {
    setFresh({ id, data: await api.findings.get(id) });
  };

  if (state.status === 'loading') {
    return (
      <p className="py-8 text-center text-sm text-fg-subtle" role="status">
        Loading finding…
      </p>
    );
  }
  if (state.status === 'error') {
    return (
      <>
        <BackLink />
        <ErrorAlert error={state.error} title="Could not load this finding" />
      </>
    );
  }
  return <FindingDetail detail={fresh?.id === id ? fresh.data : state.data} onRefresh={refresh} />;
}

function FindingDetail({
  detail,
  onRefresh,
}: {
  detail: FindingDetailResponse;
  onRefresh: () => Promise<void>;
}) {
  const { finding, advisory, history, comments, rule } = detail;
  const can = usePermissions();
  const { controls, group } = useCollapseAll();
  const r = finding.riskInputs;
  return (
    <>
      <BackLink />
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight text-fg">{finding.title}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-3 text-sm">
          <SeverityBadge severity={finding.severity} />
          <FindingStatusBadge status={finding.status} />
          <span className="text-fg-muted">{CONFIDENCE_LABELS[finding.confidence]}</span>
          <span className="text-fg-muted">
            {CATEGORY_LABELS[finding.category] ?? finding.category}
          </span>
          <span className="inline-flex items-center gap-1 text-fg-muted">
            Risk <RiskScore score={finding.riskScore} />
          </span>
        </div>
        <p className="mt-2 text-sm text-fg-muted">
          <Link
            to={`/domains/${finding.domain.id}`}
            className="font-mono text-sky-800 hover:underline"
          >
            {finding.domain.fqdn}
          </Link>
          {finding.hostname !== finding.domain.fqdn && (
            <>
              {' '}
              · host <span className="font-mono">{finding.hostname}</span>
            </>
          )}
          {finding.component && (
            <>
              {' '}
              · component <span className="font-mono">{finding.component}</span>
            </>
          )}
        </p>
        <div
          role="note"
          className="mt-3 flex gap-2 rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sm text-sky-900"
        >
          <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
          This is an observation from automated, non-intrusive checks of public data and
          internet-facing services. It describes a configuration or exposure condition; it is not
          evidence that the system has been compromised.
          {finding.category === 'software' && (
            <>
              {' '}
              The version was self-reported by the server and distributions often backport fixes
              without changing it: treat this as possibly affected and verify.
            </>
          )}
        </div>
      </div>

      <FindingWorkflow finding={finding} onRefresh={onRefresh} />

      <div className="mb-2 flex justify-end">{controls}</div>
      {group(
        <div className="grid items-start gap-4 lg:grid-cols-2">
          <Card title="What we observed" className="lg:col-span-2">
            <p className="mb-3 text-sm text-fg-2">{finding.description}</p>
            <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-fg-subtle">
              Evidence
            </h3>
            <EvidenceView evidence={finding.evidence} />
          </Card>

          <Card
            title="Why this matters"
            collapsible="finding.advisory"
            summary={
              advisory
                ? plural(advisory.recommendedActions.length, 'recommended action')
                : 'No advisory'
            }
          >
            {advisory ? (
              <div className="space-y-3 text-sm text-fg-2">
                <p>{advisory.summary}</p>
                <div>
                  <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-fg-subtle">
                    Business impact
                  </h3>
                  <p>{advisory.businessImpact}</p>
                </div>
                {advisory.recommendedActions.length > 0 && (
                  <div>
                    <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-fg-subtle">
                      Recommended actions
                    </h3>
                    <ol className="list-decimal space-y-1 pl-5">
                      {advisory.recommendedActions.map((a) => (
                        <li key={a}>{a}</li>
                      ))}
                    </ol>
                  </div>
                )}
                {advisory.references.length > 0 && (
                  <div>
                    <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-fg-subtle">
                      References
                    </h3>
                    <ul className="space-y-1">
                      {advisory.references.map((r) => (
                        <li key={r} className="break-all">
                          {/^https:\/\//.test(r) ? (
                            <a
                              href={r}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sky-800 hover:underline"
                            >
                              {r}
                            </a>
                          ) : (
                            r
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-fg-subtle">
                No advisory has been generated for this finding.
              </p>
            )}
          </Card>

          <Card
            title="Risk score"
            collapsible="finding.risk"
            defaultOpen={false}
            summary={`${finding.riskScore} = ${SEVERITY_LABELS[r.severity]} × ${EXPOSURE_LABELS[r.exposure]} × ${CRITICALITY_LABELS[r.criticality]} domain`}
          >
            <RiskExplainer detail={detail} />
          </Card>

          <Card
            title="How it is resolved"
            collapsible="finding.resolution"
            defaultOpen={false}
            summary={
              !rule
                ? 'Rule not in the catalogue'
                : finding.manualResolution
                  ? 'Resolved by a user after review'
                  : 'Resolved by a later successful scan'
            }
          >
            <div className="space-y-3 text-sm text-fg-2">
              {rule ? (
                <>
                  <p>{rule.resolution}</p>
                  <p className="text-xs text-fg-subtle">
                    {finding.manualResolution
                      ? 'This rule reports a change, so a user with triage permission resolves it after reviewing the change. Failed or incomplete scans never resolve findings.'
                      : 'A finding is only resolved by a later successful scan that confirms the condition is gone. Failed or incomplete scans never resolve findings.'}
                  </p>
                </>
              ) : (
                <p className="text-fg-subtle">
                  The rule that raised this finding is no longer in the catalogue.
                </p>
              )}
            </div>
          </Card>

          <Card
            title="Rule"
            collapsible="finding.rule"
            defaultOpen={false}
            summary={`${finding.ruleId} v${finding.ruleVersion} · last seen ${formatDateTime(finding.lastSeenAt)}`}
          >
            <dl className="space-y-2 text-sm">
              <Row label="Rule">
                <span className="font-mono">
                  {finding.ruleId} v{finding.ruleVersion}
                </span>
              </Row>
              {rule && <Row label="Detection">{rule.detection}</Row>}
              {rule && <Row label="Evidence required">{rule.evidenceRequirements}</Row>}
              <Row label="First seen">{formatDateTime(finding.firstSeenAt)}</Row>
              <Row label="Last seen">{formatDateTime(finding.lastSeenAt)}</Row>
              {finding.resolvedAt && (
                <Row label="Resolved">{formatDateTime(finding.resolvedAt)}</Row>
              )}
              <Row label="Recurrences">{finding.recurrenceCount}</Row>
            </dl>
          </Card>

          <StatusHistory history={history} />

          <FindingComments
            findingId={finding.id}
            comments={comments}
            canComment={can('findings:triage') || can('findings:remediate')}
            onAdded={onRefresh}
          />
        </div>,
      )}
    </>
  );
}

const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`;

/** Status changes, oldest first; a long history shows its latest entries until expanded. */
function StatusHistory({ history }: { history: FindingDetailResponse['history'] }) {
  const { shown, toggle } = useShowAll(history, { limit: 5, noun: 'changes', from: 'end' });
  const latest = history.at(-1);
  return (
    <Card
      title="Status history"
      className="lg:col-span-2"
      collapsible="finding.history"
      defaultOpen={false}
      summary={
        latest
          ? `${plural(history.length, 'change')} · latest ${formatDateTime(latest.createdAt)}`
          : 'No changes'
      }
    >
      {history.length === 0 ? (
        <p className="text-sm text-fg-subtle">No status changes recorded.</p>
      ) : (
        <>
          {toggle && <div className="mb-3">{toggle}</div>}
          <ol className="space-y-3 border-l border-line pl-4 text-sm">
            {shown.map((h) => (
              <li key={h.id} className="relative">
                <span
                  className="absolute -left-[1.3rem] top-1.5 size-2 rounded-full bg-slate-400"
                  aria-hidden
                />
                <div className="font-medium text-fg">
                  {h.fromStatus
                    ? `${FINDING_STATUS_LABELS[h.fromStatus]} → ${FINDING_STATUS_LABELS[h.toStatus]}`
                    : FINDING_STATUS_LABELS[h.toStatus]}
                </div>
                <div className="text-fg-muted">{historyReasonLabel(h.reason, h.changedBy)}</div>
                {h.note && (
                  <blockquote className="mt-0.5 whitespace-pre-wrap border-l-2 border-line pl-2 text-fg-2">
                    {h.note}
                  </blockquote>
                )}
                <div className="text-xs text-fg-subtle">
                  {formatDateTime(h.createdAt)} · {h.changedBy ? h.changedBy.email : 'System'}
                  {h.scanJobId && (
                    <>
                      {' '}
                      ·{' '}
                      <Link to={`/scans/${h.scanJobId}`} className="text-sky-800 hover:underline">
                        scan
                      </Link>
                    </>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </>
      )}
    </Card>
  );
}

function RiskExplainer({ detail }: { detail: FindingDetailResponse }) {
  const { riskInputs: r, riskScore } = detail.finding;
  const raw = r.severityWeight * r.exposureFactor * r.criticalityFactor;
  return (
    <div className="space-y-3 text-sm">
      <p className="text-fg-muted">
        Risk ranks findings for remediation. It is calculated from fixed factors (model {r.model})
        and is separate from severity.
      </p>
      <table className="w-full text-left" aria-label="Risk score calculation">
        <thead className="text-xs uppercase tracking-wide text-fg-subtle">
          <tr>
            <th scope="col" className="pb-1 font-medium">
              Factor
            </th>
            <th scope="col" className="pb-1 font-medium">
              Input
            </th>
            <th scope="col" className="pb-1 text-right font-medium">
              Value
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line-soft">
          <tr>
            <th scope="row" className="py-1.5 font-normal text-fg-muted">
              Severity weight
            </th>
            <td className="py-1.5 text-fg">{SEVERITY_LABELS[r.severity]}</td>
            <td className="py-1.5 text-right tabular-nums">{r.severityWeight}</td>
          </tr>
          <tr>
            <th scope="row" className="py-1.5 font-normal text-fg-muted">
              × Exposure factor
            </th>
            <td className="py-1.5 text-fg">{EXPOSURE_LABELS[r.exposure]}</td>
            <td className="py-1.5 text-right tabular-nums">{r.exposureFactor}</td>
          </tr>
          <tr>
            <th scope="row" className="py-1.5 font-normal text-fg-muted">
              × Criticality factor
            </th>
            <td className="py-1.5 text-fg">{CRITICALITY_LABELS[r.criticality]} domain</td>
            <td className="py-1.5 text-right tabular-nums">{r.criticalityFactor}</td>
          </tr>
        </tbody>
        <tfoot>
          <tr className="border-t border-line-strong">
            <th scope="row" className="pt-1.5 font-medium text-fg">
              = Risk score
            </th>
            <td className="pt-1.5 text-xs text-fg-subtle">
              {Number(raw.toFixed(2))}, rounded and capped at 0–100
            </td>
            <td className="pt-1.5 text-right font-semibold tabular-nums" data-testid="risk-total">
              {riskScore}
            </td>
          </tr>
        </tfoot>
      </table>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[9rem_1fr] sm:gap-3">
      <dt className="text-fg-subtle">{label}</dt>
      <dd className="text-fg">{children}</dd>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/findings"
      className="mb-4 inline-flex items-center gap-1 text-sm text-fg-muted hover:text-fg"
    >
      <ArrowLeft className="size-4" aria-hidden />
      Findings
    </Link>
  );
}
