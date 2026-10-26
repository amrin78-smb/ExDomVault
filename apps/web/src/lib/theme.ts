import { useCallback, useSyncExternalStore } from 'react';

export type Theme = 'dark' | 'light';

/** localStorage key holding the viewer's theme choice. */
export const THEME_STORAGE_KEY = 'exdv.theme';
export const DEFAULT_THEME: Theme = 'dark';

/** The stored choice, or the default when nothing (valid) is stored or storage is unavailable. */
export function readStoredTheme(): Theme {
  try {
    const v = window.localStorage.getItem(THEME_STORAGE_KEY);
    return v === 'light' || v === 'dark' ? v : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

const listeners = new Set<() => void>();

/** Applies a theme to <html> (the `dark` class drives every `dark:` variant and token). */
export function applyTheme(theme: Theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark');
  for (const l of listeners) l();
}

/** Called once in main.tsx before the first render, so the page never flashes the wrong theme. */
export function initTheme() {
  applyTheme(readStoredTheme());
}

/** Applies and remembers a theme (the choice lasts for this page only if storage is blocked). */
export function setTheme(theme: Theme) {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Storage unavailable (private window, blocked site data).
  }
  applyTheme(theme);
}

const currentTheme = (): Theme =>
  document.documentElement.classList.contains('dark') ? 'dark' : 'light';

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The theme currently applied to the document, and a setter that also remembers it. */
export function useTheme(): [Theme, (theme: Theme) => void] {
  const theme = useSyncExternalStore(subscribe, currentTheme, currentTheme);
  return [theme, useCallback((t: Theme) => setTheme(t), [])];
}
