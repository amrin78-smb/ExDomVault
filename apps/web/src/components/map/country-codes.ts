/**
 * ISO 3166-1 alpha-2 → numeric (as zero-padded strings, the ids used by `world-atlas`). All 249
 * assigned codes, generated from the iso-codes package (Debian `iso-codes`, ISO 3166-1). `XK`
 * (Kosovo) has no ISO numeric code; world-atlas ships it without an id, matched by name instead.
 */
// prettier-ignore
export const ALPHA2_TO_NUMERIC: Readonly<Record<string, string>> = {
  AD: '020', AE: '784', AF: '004', AG: '028', AI: '660', AL: '008', AM: '051', AO: '024',
  AQ: '010', AR: '032', AS: '016', AT: '040', AU: '036', AW: '533', AX: '248', AZ: '031',
  BA: '070', BB: '052', BD: '050', BE: '056', BF: '854', BG: '100', BH: '048', BI: '108',
  BJ: '204', BL: '652', BM: '060', BN: '096', BO: '068', BQ: '535', BR: '076', BS: '044',
  BT: '064', BV: '074', BW: '072', BY: '112', BZ: '084', CA: '124', CC: '166', CD: '180',
  CF: '140', CG: '178', CH: '756', CI: '384', CK: '184', CL: '152', CM: '120', CN: '156',
  CO: '170', CR: '188', CU: '192', CV: '132', CW: '531', CX: '162', CY: '196', CZ: '203',
  DE: '276', DJ: '262', DK: '208', DM: '212', DO: '214', DZ: '012', EC: '218', EE: '233',
  EG: '818', EH: '732', ER: '232', ES: '724', ET: '231', FI: '246', FJ: '242', FK: '238',
  FM: '583', FO: '234', FR: '250', GA: '266', GB: '826', GD: '308', GE: '268', GF: '254',
  GG: '831', GH: '288', GI: '292', GL: '304', GM: '270', GN: '324', GP: '312', GQ: '226',
  GR: '300', GS: '239', GT: '320', GU: '316', GW: '624', GY: '328', HK: '344', HM: '334',
  HN: '340', HR: '191', HT: '332', HU: '348', ID: '360', IE: '372', IL: '376', IM: '833',
  IN: '356', IO: '086', IQ: '368', IR: '364', IS: '352', IT: '380', JE: '832', JM: '388',
  JO: '400', JP: '392', KE: '404', KG: '417', KH: '116', KI: '296', KM: '174', KN: '659',
  KP: '408', KR: '410', KW: '414', KY: '136', KZ: '398', LA: '418', LB: '422', LC: '662',
  LI: '438', LK: '144', LR: '430', LS: '426', LT: '440', LU: '442', LV: '428', LY: '434',
  MA: '504', MC: '492', MD: '498', ME: '499', MF: '663', MG: '450', MH: '584', MK: '807',
  ML: '466', MM: '104', MN: '496', MO: '446', MP: '580', MQ: '474', MR: '478', MS: '500',
  MT: '470', MU: '480', MV: '462', MW: '454', MX: '484', MY: '458', MZ: '508', NA: '516',
  NC: '540', NE: '562', NF: '574', NG: '566', NI: '558', NL: '528', NO: '578', NP: '524',
  NR: '520', NU: '570', NZ: '554', OM: '512', PA: '591', PE: '604', PF: '258', PG: '598',
  PH: '608', PK: '586', PL: '616', PM: '666', PN: '612', PR: '630', PS: '275', PT: '620',
  PW: '585', PY: '600', QA: '634', RE: '638', RO: '642', RS: '688', RU: '643', RW: '646',
  SA: '682', SB: '090', SC: '690', SD: '729', SE: '752', SG: '702', SH: '654', SI: '705',
  SJ: '744', SK: '703', SL: '694', SM: '674', SN: '686', SO: '706', SR: '740', SS: '728',
  ST: '678', SV: '222', SX: '534', SY: '760', SZ: '748', TC: '796', TD: '148', TF: '260',
  TG: '768', TH: '764', TJ: '762', TK: '772', TL: '626', TM: '795', TN: '788', TO: '776',
  TR: '792', TT: '780', TV: '798', TW: '158', TZ: '834', UA: '804', UG: '800', UM: '581',
  US: '840', UY: '858', UZ: '860', VA: '336', VC: '670', VE: '862', VG: '092', VI: '850',
  VN: '704', VU: '548', WF: '876', WS: '882', YE: '887', YT: '175', ZA: '710', ZM: '894',
  ZW: '716',
};

/**
 * Approximate [longitude, latitude] for codes that `countries-110m` omits (small states and
 * territories), so their bubble still appears. Display-only; a degree or so off is fine.
 */
// prettier-ignore
export const SMALL_COUNTRY_POINTS: Readonly<Record<string, readonly [number, number]>> = {
  AD: [1.6, 42.5], AG: [-61.8, 17.1], AI: [-63.1, 18.2], AS: [-170.7, -14.3], AW: [-70.0, 12.5],
  AX: [19.9, 60.2], BB: [-59.6, 13.2], BH: [50.6, 26.0], BL: [-62.8, 17.9], BM: [-64.8, 32.3],
  BQ: [-68.3, 12.2], BV: [3.4, -54.4], CC: [96.8, -12.2], CK: [-159.8, -21.2], CV: [-23.6, 15.1],
  CW: [-69.0, 12.2], CX: [105.7, -10.5], DM: [-61.4, 15.4], FM: [158.2, 6.9], FO: [-6.9, 62.0],
  GD: [-61.7, 12.1], GF: [-53.1, 4.0], GG: [-2.6, 49.5], GI: [-5.4, 36.1], GP: [-61.6, 16.2],
  GS: [-36.6, -54.4], GU: [144.8, 13.4], HK: [114.2, 22.3], HM: [73.5, -53.1], IM: [-4.5, 54.2],
  IO: [72.4, -7.3], JE: [-2.1, 49.2], KI: [-157.4, 1.9], KM: [43.3, -11.7], KN: [-62.8, 17.3],
  KY: [-81.3, 19.3], LC: [-61.0, 13.9], LI: [9.6, 47.2], MC: [7.4, 43.7], MF: [-63.1, 18.1],
  MH: [171.2, 7.1], MO: [113.5, 22.2], MP: [145.7, 15.2], MQ: [-61.0, 14.6], MS: [-62.2, 16.7],
  MT: [14.4, 35.9], MU: [57.6, -20.3], MV: [73.5, 4.2], NF: [168.0, -29.0], NR: [166.9, -0.5],
  NU: [-169.9, -19.1], PF: [-149.4, -17.7], PM: [-56.3, 46.9], PN: [-130.1, -25.1], PW: [134.6, 7.5],
  RE: [55.5, -21.1], SC: [55.5, -4.7], SG: [103.8, 1.35], SH: [-5.7, -15.9], SJ: [16.0, 78.2],
  SM: [12.5, 43.9], ST: [6.6, 0.3], SX: [-63.1, 18.0], TC: [-71.8, 21.8], TK: [-171.8, -9.2],
  TO: [-175.2, -21.2], TV: [179.2, -8.5], UM: [-162.0, 5.9], VA: [12.45, 41.9], VC: [-61.2, 13.2],
  VG: [-64.6, 18.4], VI: [-64.9, 18.3], WF: [-176.2, -13.3], WS: [-172.1, -13.8], YT: [45.2, -12.8],
};

/** Centroids pulled off-centre by remote territories in the 110m shapes (Alaska, French Guiana…). */
export const POINT_OVERRIDES: Readonly<Record<string, readonly [number, number]>> = {
  US: [-98.5, 39.5],
  FR: [2.5, 46.6],
  NO: [9.5, 61.5],
};

const NUMERIC_TO_ALPHA2: ReadonlyMap<string, string> = new Map(
  Object.entries(ALPHA2_TO_NUMERIC).map(([a, n]) => [n, a]),
);

/** Alpha-2 code of a world-atlas feature (numeric id, or Kosovo by name), else null. */
export function alpha2OfFeature(id: string | number | undefined, name?: string): string | null {
  if (id !== undefined) return NUMERIC_TO_ALPHA2.get(String(id).padStart(3, '0')) ?? null;
  return name === 'Kosovo' ? 'XK' : null;
}
