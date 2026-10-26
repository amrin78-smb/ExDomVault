/** Regional-indicator flag for an ISO 3166-1 alpha-2 code, e.g. "DE" → 🇩🇪. */
const flagOf = (code: string) =>
  String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));

/** Country of an IP address (from the worker's geolocation): flag plus the code as text. */
export function CountryFlag({ code }: { code: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 whitespace-nowrap text-xs text-fg-subtle"
      title={`Geolocated to ${code}`}
    >
      <span aria-hidden>{flagOf(code)}</span>
      <span>
        <span className="sr-only">Country </span>
        {code}
      </span>
    </span>
  );
}
