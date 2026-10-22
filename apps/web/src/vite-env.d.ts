/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Set to "true" in apps/web/.env.development.local to render labelled dev fixtures. Ignored in production builds. */
  readonly VITE_DEV_FIXTURES?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
