import { DBIP_ATTRIBUTION } from '@exdomainvault/shared';
import { geoCentroid, geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo';
import type { Feature, FeatureCollection, Geometry } from 'geojson';
import { Minus, Plus, RotateCcw } from 'lucide-react';
import { useId, useMemo, useRef, useState, type PointerEvent } from 'react';
import { feature } from 'topojson-client';
import type { GeometryCollection } from 'topojson-specification';
import topology from 'world-atlas/countries-110m.json';
import { alpha2OfFeature, POINT_OVERRIDES, SMALL_COUNTRY_POINTS } from './country-codes.ts';
import { countryName } from './country-names.ts';
import type { WorldMapCountry, WorldMapProps } from './types.ts';

/**
 * Choropleth + bubble world map (Milestone 13). Countries are shaded by asset count on a
 * sequential blue scale; a glowing dot at each country's centroid is sized by IP count. Pure SVG
 * (d3-geo for the projection, no d3-zoom): +/− buttons zoom about the centre and dragging pans.
 * Whenever country data is drawn, the DB-IP attribution its licence (CC BY 4.0) requires is shown.
 *
 * This module embeds the world-atlas topology (~100 KB): import `LazyWorldMap` instead so it loads
 * in its own chunk.
 */

const W = 960;
const H = 470;
const MIN_ZOOM = 1;
const MAX_ZOOM = 8;
const ZOOM_STEP = 1.6;

type CountryFeature = Feature<Geometry, { name: string }>;

const countries = feature(
  topology,
  topology.objects.countries as GeometryCollection<{ name: string }>,
) as FeatureCollection<Geometry, { name: string }>;
// Antarctica takes a fifth of the frame and never hosts assets of interest; leave it out.
const shapes = countries.features.filter((f) => f.id !== '010');
const projection = geoNaturalEarth1().fitExtent(
  [
    [4, 4],
    [W - 4, H - 4],
  ],
  { type: 'FeatureCollection', features: shapes },
);
const path = geoPath(projection);
const SHAPES = shapes.map((f: CountryFeature) => ({
  code: alpha2OfFeature(f.id, f.properties.name),
  name: f.properties.name,
  d: path(f) ?? '',
  centroid: geoCentroid(f),
}));
const SPHERE = path({ type: 'Sphere' }) ?? '';
const GRATICULE = path(geoGraticule10()) ?? '';

/** Sequential scale, low → high. Literal classes so Tailwind generates them (no inline styles). */
const FILL_STEPS = [
  'fill-[color-mix(in_oklab,#3b82f6_22%,var(--color-surface-3))]',
  'fill-[color-mix(in_oklab,#3b82f6_40%,var(--color-surface-3))]',
  'fill-[color-mix(in_oklab,#3b82f6_58%,var(--color-surface-3))]',
  'fill-[color-mix(in_oklab,#3b82f6_78%,var(--color-surface-3))]',
  'fill-[#3b82f6]',
] as const;
const SWATCH_STEPS = [
  'bg-[color-mix(in_oklab,#3b82f6_22%,var(--color-surface-3))]',
  'bg-[color-mix(in_oklab,#3b82f6_40%,var(--color-surface-3))]',
  'bg-[color-mix(in_oklab,#3b82f6_58%,var(--color-surface-3))]',
  'bg-[color-mix(in_oklab,#3b82f6_78%,var(--color-surface-3))]',
  'bg-[#3b82f6]',
] as const;

const stepOf = (assets: number, max: number) =>
  max <= 0 ? 0 : Math.min(FILL_STEPS.length - 1, Math.floor(Math.sqrt(assets / max) * 5));

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

const round = (n: number) => Math.round(n * 100) / 100;

interface View {
  k: number;
  x: number;
  y: number;
}

/** Keeps the zoomed map covering the frame (no panning past its edges). */
function clamp(v: View): View {
  const clampAxis = (t: number, size: number) => Math.min(0, Math.max(size - size * v.k, t));
  return { k: v.k, x: clampAxis(v.x, W), y: clampAxis(v.y, H) };
}

function zoomTo(v: View, k: number): View {
  const raw = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, k));
  const next = Math.abs(raw - MIN_ZOOM) < 1e-6 ? MIN_ZOOM : raw;
  const ratio = next / v.k;
  return clamp({ k: next, x: W / 2 - (W / 2 - v.x) * ratio, y: H / 2 - (H / 2 - v.y) * ratio });
}

export function WorldMap({
  countries: data,
  height,
  compact = false,
  attribution,
  label = 'World map of assets by country',
}: WorldMapProps) {
  const filterId = `glow-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  const [view, setView] = useState<View>({ k: 1, x: 0, y: 0 });
  const [hover, setHover] = useState<string | null>(null);
  const drag = useRef<{ id: number; x: number; y: number; view: View } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const byCode = useMemo(() => new Map(data.map((c) => [c.country, c])), [data]);
  const maxAssets = Math.max(0, ...data.map((c) => c.assets));
  const maxIps = Math.max(0, ...data.map((c) => c.ips));

  const points = useMemo(() => {
    const out: { c: WorldMapCountry; x: number; y: number }[] = [];
    for (const c of data) {
      const lonLat =
        POINT_OVERRIDES[c.country] ??
        SMALL_COUNTRY_POINTS[c.country] ??
        SHAPES.find((s) => s.code === c.country)?.centroid;
      const xy = lonLat ? projection([lonLat[0], lonLat[1]]) : null;
      if (xy) out.push({ c, x: xy[0], y: xy[1] });
    }
    // Large bubbles first so small ones stay on top and hoverable.
    return out.sort((a, b) => b.c.ips - a.c.ips);
  }, [data]);

  const hovered = hover ? byCode.get(hover) : undefined;
  const hoveredPoint = hover ? points.find((p) => p.c.country === hover) : undefined;

  const onPointerDown = (e: PointerEvent<SVGSVGElement>) => {
    if (compact || view.k === 1) return;
    drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY, view };
    e.currentTarget.setPointerCapture?.(e.pointerId);
  };
  const onPointerMove = (e: PointerEvent<SVGSVGElement>) => {
    const d = drag.current;
    if (!d || d.id !== e.pointerId) return;
    const rect = svgRef.current?.getBoundingClientRect();
    const scale = rect && rect.width > 0 ? W / rect.width : 1;
    setView(
      clamp({
        k: d.view.k,
        x: d.view.x + (e.clientX - d.x) * scale,
        y: d.view.y + (e.clientY - d.y) * scale,
      }),
    );
  };
  const endDrag = () => {
    drag.current = null;
  };

  const radius = (ips: number) => {
    const base = compact ? 2.5 : 3.5;
    const span = compact ? 7 : 11;
    return (base + (maxIps > 0 ? Math.sqrt(ips / maxIps) * span : 0)) / Math.sqrt(view.k);
  };

  return (
    <div className="relative">
      <div className="relative overflow-hidden rounded-lg border border-line-soft bg-surface-2">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          role="group"
          aria-label={label}
          className={`block w-full select-none ${view.k > 1 ? 'cursor-grab active:cursor-grabbing' : ''}`}
          height={height}
          preserveAspectRatio="xMidYMid meet"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
          onMouseLeave={() => setHover(null)}
        >
          <defs>
            <filter id={filterId} x="-100%" y="-100%" width="300%" height="300%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <g
            data-testid="map-viewport"
            transform={`translate(${round(view.x)} ${round(view.y)}) scale(${round(view.k)})`}
          >
            <path d={SPHERE} className="fill-surface-2" />
            <path
              d={GRATICULE}
              className="fill-none stroke-line-soft"
              strokeWidth={0.5}
              vectorEffect="non-scaling-stroke"
            />
            {SHAPES.map((s, i) => {
              const c = s.code ? byCode.get(s.code) : undefined;
              const name = s.code ? countryName(s.code) : s.name;
              return (
                <path
                  key={s.code ?? `x${i}`}
                  d={s.d}
                  data-country={s.code ?? undefined}
                  className={`stroke-line-strong transition-colors ${
                    c
                      ? `${FILL_STEPS[stepOf(c.assets, maxAssets)]} cursor-pointer hover:brightness-125 focus:outline-none`
                      : 'fill-surface-3'
                  } ${hover && hover === s.code ? 'stroke-highlight' : ''}`}
                  strokeWidth={hover && hover === s.code ? 1.2 : 0.4}
                  vectorEffect="non-scaling-stroke"
                  {...(c
                    ? {
                        tabIndex: 0,
                        role: 'img',
                        'aria-label': `${name}: ${plural(c.assets, 'asset')}, ${plural(c.ips, 'IP')}`,
                        onMouseEnter: () => setHover(c.country),
                        onFocus: () => setHover(c.country),
                        onBlur: () => setHover(null),
                      }
                    : { 'aria-hidden': true })}
                />
              );
            })}
            {points.map(({ c, x, y }) => (
              <g key={c.country} aria-hidden>
                {!compact && (
                  <circle
                    cx={x}
                    cy={y}
                    r={radius(c.ips) * 1.9}
                    className="pointer-events-none fill-highlight opacity-15"
                  />
                )}
                <circle
                  cx={x}
                  cy={y}
                  r={radius(c.ips)}
                  filter={`url(#${filterId})`}
                  className="cursor-pointer fill-highlight stroke-surface opacity-90"
                  strokeWidth={0.8}
                  vectorEffect="non-scaling-stroke"
                  onMouseEnter={() => setHover(c.country)}
                />
              </g>
            ))}
          </g>
        </svg>

        {hovered && hoveredPoint && (
          <div
            role="tooltip"
            className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-md border border-line bg-surface px-2.5 py-1.5 text-xs shadow-pop"
            style={{
              left: `${((hoveredPoint.x * view.k + view.x) / W) * 100}%`,
              top: `calc(${((hoveredPoint.y * view.k + view.y) / H) * 100}% - 10px)`,
            }}
          >
            <div className="font-medium text-fg">{countryName(hovered.country)}</div>
            <div className="mt-0.5 tabular-nums text-fg-muted">
              {plural(hovered.assets, 'asset')} · {plural(hovered.ips, 'IP')}
            </div>
          </div>
        )}

        {!compact && (
          <div className="absolute right-2 top-2 flex flex-col overflow-hidden rounded-md border border-line bg-surface shadow-card">
            <button
              type="button"
              aria-label="Zoom in"
              disabled={view.k >= MAX_ZOOM}
              onClick={() => setView((v) => zoomTo(v, v.k * ZOOM_STEP))}
              className="grid size-8 place-items-center text-fg-muted hover:bg-surface-3 hover:text-fg disabled:opacity-40"
            >
              <Plus className="size-4" aria-hidden />
            </button>
            <button
              type="button"
              aria-label="Zoom out"
              disabled={view.k <= MIN_ZOOM}
              onClick={() => setView((v) => zoomTo(v, v.k / ZOOM_STEP))}
              className="grid size-8 place-items-center border-t border-line text-fg-muted hover:bg-surface-3 hover:text-fg disabled:opacity-40"
            >
              <Minus className="size-4" aria-hidden />
            </button>
            <button
              type="button"
              aria-label="Reset map view"
              disabled={view.k === 1}
              onClick={() => setView({ k: 1, x: 0, y: 0 })}
              className="grid size-8 place-items-center border-t border-line text-fg-muted hover:bg-surface-3 hover:text-fg disabled:opacity-40"
            >
              <RotateCcw className="size-3.5" aria-hidden />
            </button>
          </div>
        )}
      </div>

      <div className="mt-2 flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-xs text-fg-subtle">
        {!compact && data.length > 0 && (
          <div className="flex items-center gap-2" aria-hidden>
            <span>Fewer assets</span>
            <span className="flex overflow-hidden rounded-sm">
              {SWATCH_STEPS.map((cls) => (
                <span key={cls} className={`h-2 w-5 ${cls}`} />
              ))}
            </span>
            <span>More</span>
            <span className="ml-2 inline-block size-2 rounded-full bg-highlight" />
            <span>Dot size: IPs</span>
          </div>
        )}
        {data.length > 0 && (
          <a
            href="https://db-ip.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-fg-subtle underline-offset-2 hover:text-fg-muted hover:underline"
          >
            {attribution || DBIP_ATTRIBUTION}
          </a>
        )}
      </div>
    </div>
  );
}

export default WorldMap;
