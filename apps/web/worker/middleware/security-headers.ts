import { createMiddleware } from 'hono/factory';
import type { AppBindings } from '../types.ts';

/**
 * API responses are JSON only: nothing in them may be rendered, framed or run as a document.
 * The SPA's HTML and assets get their (looser, but still strict) policy from `public/_headers`,
 * which Workers static assets apply to asset responses; the Worker never serves HTML.
 */
export const API_CONTENT_SECURITY_POLICY =
  "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

export const PERMISSIONS_POLICY =
  'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), browsing-topics=()';

/** Baseline security headers for API responses. */
export const securityHeaders = () =>
  createMiddleware<AppBindings>(async (c, next) => {
    await next();
    c.header('Content-Security-Policy', API_CONTENT_SECURITY_POLICY);
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('X-Frame-Options', 'DENY');
    c.header('Cross-Origin-Opener-Policy', 'same-origin');
    c.header('Cross-Origin-Resource-Policy', 'same-origin');
    c.header('Permissions-Policy', PERMISSIONS_POLICY);
    c.header('Cache-Control', 'no-store');
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  });
