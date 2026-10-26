/** At most this many bars; longer series are sampled (last value of each bucket). */
export const MAX_BARS = 30;

/** Point-in-time counts: each bucket keeps its last value (the level at the end of the bucket). */
export function sampleSeries(series: readonly number[], max = MAX_BARS): number[] {
  if (series.length <= max) return [...series];
  const size = series.length / max;
  return Array.from(
    { length: max },
    (_, i) => series[Math.min(series.length - 1, Math.ceil((i + 1) * size) - 1)] ?? 0,
  );
}
