// Vite/Vitest `?raw` imports (used by tests to read non-TS files as text).
declare module '*?raw' {
  const text: string;
  export default text;
}
