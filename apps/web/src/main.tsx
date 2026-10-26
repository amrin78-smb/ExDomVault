import '@fontsource-variable/inter';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider, createBrowserRouter } from 'react-router';
import { DataModeProvider } from './lib/DataModeProvider.tsx';
import { initTheme } from './lib/theme.ts';
import { routes } from './routes.tsx';
import './index.css';

// Before the first render: the CSP forbids an inline script in index.html, so the theme class is
// applied here, ahead of React mounting anything.
initTheme();

const router = createBrowserRouter(routes);

const root = document.getElementById('root');
if (!root) throw new Error('Root element #root not found');

createRoot(root).render(
  <StrictMode>
    <DataModeProvider>
      <RouterProvider router={router} />
    </DataModeProvider>
  </StrictMode>,
);
