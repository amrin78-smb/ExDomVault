# Security score

Milestone 14. Every scanned domain gets a score from 0 to 100 and a grade from A to F that summarise
its current external posture. The score is **deterministic and explainable**: it is computed only from
the domain's non-resolved findings (which come only from the deterministic rules engine), and the API
returns every deduction that produced it. It is a posture summary for prioritisation and reporting; it
never changes a finding's severity or risk score.

Implementation: `computeSecurityScore` in `packages/shared/src/domain/security-score.ts` (pure, unit
tested), server in `apps/web/worker/services/security-score.ts`.

## Formula (version 1)

```
score = clamp(0, 100, round(100 − Σ over categories of min(40, category deduction)))
category deduction = Σ over the category's non-resolved findings of weight(severity) × multiplier(state)
```

| Severity      | Weight (points per finding) |
| ------------- | --------------------------- |
| critical      | 25                          |
| high          | 10                          |
| medium        | 4                           |
| low           | 1                           |
| informational | 0                           |

| Finding state                                                               | Multiplier  |
| --------------------------------------------------------------------------- | ----------- |
| open, acknowledged, remediation in progress (not overdue)                   | 1           |
| overdue (past its [remediation SLA](api-specification.md) due date)         | 1.5         |
| accepted risk (formally accepted with a review date; never counted overdue) | 0.25        |
| resolved                                                                    | not counted |

**Category cap.** Deductions are summed per rule category (`dns`, `email`, `tls`, `http`, `exposure`,
`registration`, `asset`, `software`) and each category deducts at most **40** points, so one noisy rule
or category (for example many hostnames with the same header finding) cannot zero the score on its own.
Several weak categories still can.

**Grades.** A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F (on the rounded score).

**Examples.** No open findings → 100 (A). One overdue high finding → 100 − 15 = 85 (B). Fifty open
medium email findings → 200 points capped to 40 → 60 (D). One critical accepted risk → 100 − 6.25 →
94 (A).

## Which domains are scored

Only domains with at least one successfully completed, rules-evaluated scan job. A domain nobody has
scanned would otherwise read as "no findings → A". Unscored domains show `—` and can be filtered with
`grade=none`.

## Snapshots and trend

`domain_score_snapshots` holds one row per domain per UTC day (unique on domain + day). The 5-minute
cron step `security_scores_snapshotted` recomputes all scored domains in one aggregate statement and
upserts today's rows, at most once an hour (it runs when a scored domain has no row for today or
today's row is older than an hour; `created_at` records when the day's value was last computed). The
latest snapshot is the `score`/`grade` shown in domain lists and used by reports;
`GET /api/v1/domains/:id/score` computes the current value live, writes today's snapshot if it is
missing, and returns the 90-day trend. Each snapshot stores its inputs (`{ version, findings: [{ category,
severity, state, count }] }`) so any stored score can be re-derived.

Aggregations: the reports summary gives each business owner the mean latest score of its scored
domains, the grade of that mean, and the grade distribution; the monthly report uses each domain's last
snapshot of the month and compares the average with the previous month's.

## Limitations

- Severity and category are the finding's current values; a severity change re-scores from the next
  snapshot.
- "Overdue" uses the current SLA policy's due dates (`findings.due_at`); a policy change re-scores
  immediately for live views and from the next hourly snapshot for lists.
- Snapshots are never pruned yet (about 340 rows per day for the current portfolio).
