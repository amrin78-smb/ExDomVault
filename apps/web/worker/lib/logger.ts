export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  /** A logger whose lines also carry `fields` (e.g. a job or worker ID for correlation). */
  child(fields: Record<string, unknown>): Logger;
}

export const REDACTED = '[redacted]';

/**
 * Field names whose values are never written to logs, whatever their content: credentials, tokens,
 * signatures, cookies, raw headers and bodies, connection strings. Matched case-insensitively on the
 * key alone (`keyId`, a public credential identifier, is deliberately not matched).
 */
const SENSITIVE_KEY =
  /^(authorization|cookie|set-cookie|headers?|body|password|passphrase|secret|token|jwt|signature|private_?key|api_?key|connection_?string|database_?url|cf-access-jwt-assertion|.*(token|secret|password|signature|privatekey|apikey|jwt|cookie)s?)$/i;

/** Credential-shaped substrings in free text (error messages): connection URLs, bearer tokens, JWTs. */
const SENSITIVE_TEXT: [RegExp, string][] = [
  [/\b(postgres(?:ql)?|mysql|redis|https?):\/\/[^\s:@/]+:[^\s@/]+@/gi, '$1://[redacted]@'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, '[redacted-jwt]'],
];

const MAX_DEPTH = 6;
const MAX_STRING = 2000;

export function redactText(value: string): string {
  let out = value;
  for (const [pattern, replacement] of SENSITIVE_TEXT) out = out.replace(pattern, replacement);
  return out.length > MAX_STRING ? `${out.slice(0, MAX_STRING)}…` : out;
}

/** Deep copy of `value` with sensitive keys replaced and credential-shaped text masked. */
export function redact(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return redactText(value);
  if (value === null || typeof value !== 'object') return value;
  if (value instanceof Date) return value.toISOString();
  if (depth >= MAX_DEPTH) return '[truncated]';
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value instanceof Error) return errorFields(value);
  if (typeof Headers !== 'undefined' && value instanceof Headers) return REDACTED;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SENSITIVE_KEY.test(k) ? REDACTED : redact(v, depth + 1);
  }
  return out;
}

/** PostgreSQL error carrying a SQLSTATE (node-postgres / PGlite), possibly wrapped by Drizzle. */
function sqlStateOf(err: unknown): string | null {
  for (let e = err, i = 0; e && typeof e === 'object' && i < 4; i++) {
    const code = (e as { code?: unknown }).code;
    if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) return code;
    e = (e as { cause?: unknown }).cause;
  }
  return null;
}

/**
 * Safe log fields for an error. Database errors are reduced to their class (name + SQLSTATE): a
 * Drizzle query error's message contains the SQL text and bound parameters, which must not be logged.
 * Other messages are kept, with credential-shaped text masked.
 */
export function errorFields(err: unknown): Record<string, unknown> {
  if (!(err instanceof Error)) return { error: redactText(String(err)) };
  const sqlState = sqlStateOf(err);
  if (sqlState || err.name === 'DrizzleQueryError') {
    return { errorName: err.name, ...(sqlState ? { sqlState } : {}) };
  }
  return { errorName: err.name, error: redactText(err.message) };
}

/** Structured JSON logger. Every line carries the request ID for correlation. Never log secrets. */
export function createLogger(base: Record<string, unknown>): Logger {
  const write = (level: LogLevel, message: string, fields?: Record<string, unknown>) => {
    const line = JSON.stringify({
      level,
      message,
      time: new Date().toISOString(),
      ...(redact(base) as Record<string, unknown>),
      ...(fields ? (redact(fields) as Record<string, unknown>) : {}),
    });
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
  };
  return {
    debug: (message, fields) => write('debug', message, fields),
    info: (message, fields) => write('info', message, fields),
    warn: (message, fields) => write('warn', message, fields),
    error: (message, fields) => write('error', message, fields),
    child: (fields) => createLogger({ ...base, ...fields }),
  };
}
