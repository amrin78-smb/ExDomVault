import { Construction } from 'lucide-react';
import type { NavItem } from '../components/layout/nav.ts';
import { Card } from '../components/ui/Card.tsx';
import { EmptyState } from '../components/ui/EmptyState.tsx';
import { PageHeader } from '../components/ui/PageHeader.tsx';

/** Stand-in for sections that are not implemented yet. States plainly when they arrive. */
export function PlaceholderPage({ item }: { item: NavItem }) {
  return (
    <>
      <PageHeader title={item.label} description={item.description} />
      <Card>
        <EmptyState title={`${item.label} is not available yet`} icon={Construction}>
          This section is implemented in {item.milestone}.
        </EmptyState>
      </Card>
    </>
  );
}
