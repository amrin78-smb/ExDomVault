/** The single row an INSERT/UPDATE … RETURNING must produce. Missing it is a programming error. */
export function firstRow<T>(rows: T[]): T {
  const [row] = rows;
  if (row === undefined) throw new Error('Expected the statement to return a row');
  return row;
}
