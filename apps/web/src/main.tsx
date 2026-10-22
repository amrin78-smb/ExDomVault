import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider, createBrowserRouter } from 'react-router';
import { DataModeProvider } from './lib/DataModeProvider.tsx';
import { routes } from './routes.tsx';
import './index.css';

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
