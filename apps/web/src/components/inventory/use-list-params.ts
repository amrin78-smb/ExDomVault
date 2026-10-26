import { useSearchParams } from 'react-router';

/**
 * URL-synced list state for the inventory pages: every filter, the sort and the page live in the
 * query string, so a view is shareable and Back restores it. Changing anything but the page
 * returns to page 1; an empty value removes the key.
 */
export function useListParams() {
  const [params, setParams] = useSearchParams();
  const get = (key: string) => params.get(key) ?? undefined;
  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next);
  };
  return { params, get, setParam };
}
