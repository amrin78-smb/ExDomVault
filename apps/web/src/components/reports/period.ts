const monthFmt = new Intl.DateTimeFormat(undefined, {
  month: 'long',
  year: 'numeric',
  timeZone: 'UTC',
});

/** "October 2026" for "2026-10". */
export const periodLabel = (period: string) => monthFmt.format(new Date(`${period}-01T00:00:00Z`));
