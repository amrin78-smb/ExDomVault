import { Button } from '../ui/Button.tsx';

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
}) {
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <nav
      aria-label="Pagination"
      className="mt-4 flex items-center justify-between border-t border-line-soft pt-3 text-sm text-fg-muted"
    >
      <span>
        {first}–{last} of {total}
      </span>
      <div className="flex gap-2">
        <Button onClick={() => onPage(page - 1)} disabled={page <= 1}>
          Previous
        </Button>
        <Button onClick={() => onPage(page + 1)} disabled={page >= pages}>
          Next
        </Button>
      </div>
    </nav>
  );
}
