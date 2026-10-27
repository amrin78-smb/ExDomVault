/** One country on the map: ISO 3166-1 alpha-2 code with its asset and IP counts. */
export interface WorldMapCountry {
  country: string;
  assets: number;
  ips: number;
}

export interface WorldMapProps {
  countries: readonly WorldMapCountry[];
  /** Rendered SVG height in px; the width always fills the container (aspect ratio kept). */
  height?: number;
  /** Dashboard size: smaller dots, no zoom controls or scale legend (attribution stays). */
  compact?: boolean;
  /**
   * Geolocation licence attribution (e.g. `geoAttribution` from the API). Defaults to the DB-IP
   * text; it cannot be turned off — the CC BY 4.0 licence requires it whenever data is shown.
   */
  attribution?: string;
  /** Accessible name of the map. */
  label?: string;
  /** Called with the alpha-2 code when a country with data (shape or bubble) is clicked/activated. */
  onSelectCountry?: (country: string) => void;
}
