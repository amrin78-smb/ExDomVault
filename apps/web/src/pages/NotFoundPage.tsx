import { Link } from 'react-router';
import { PageHeader } from '../components/ui/PageHeader.tsx';

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" description="The page you requested does not exist." />
      <Link to="/" className="text-sm font-medium text-sky-700 hover:underline">
        Return to the overview
      </Link>
    </>
  );
}
