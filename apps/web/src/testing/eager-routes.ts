// Test-only: the app's routes with every lazily loaded page resolved up front, so tests can render
// a route synchronously. Production code splits pages (routes.tsx); this also proves every lazy
// import resolves to a component.
import type { RouteObject } from 'react-router';
import { routes as lazyRoutes } from '../routes.tsx';

async function resolve(list: RouteObject[]): Promise<RouteObject[]> {
  return Promise.all(
    list.map(async (route) => {
      const { lazy, children, ...rest } = route as RouteObject & { lazy?: () => Promise<object> };
      const loaded = typeof lazy === 'function' ? await lazy() : {};
      const kids = children ? await resolve(children) : undefined;
      return { ...rest, ...loaded, ...(kids ? { children: kids } : {}) } as RouteObject;
    }),
  );
}

export const routes = await resolve(lazyRoutes);
