import { useEffect, useState } from 'react';

const isVisible = () => typeof document === 'undefined' || document.visibilityState !== 'hidden';

/** Whether the browser tab is visible, so polling can pause in background tabs. */
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(isVisible);
  useEffect(() => {
    const update = () => setVisible(isVisible());
    document.addEventListener('visibilitychange', update);
    return () => document.removeEventListener('visibilitychange', update);
  }, []);
  return visible;
}
