// world-atlas ships TopoJSON without types; the map reads it as a TopoJSON topology.
declare module 'world-atlas/countries-110m.json' {
  import type { Topology } from 'topojson-specification';
  const topology: Topology;
  export default topology;
}
