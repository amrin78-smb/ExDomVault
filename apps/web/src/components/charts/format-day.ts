const shortDate = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  timeZone: 'UTC',
});
const longDate = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeZone: 'UTC' });
/** `YYYY-MM-DD` (a UTC day) as "Oct 3". */
export const formatDay = (day: string) => shortDate.format(new Date(`${day}T00:00:00Z`));
export const formatLongDay = (day: string) => longDate.format(new Date(`${day}T00:00:00Z`));
