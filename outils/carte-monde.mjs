// Fabrique web/carte-monde.js : le contour des pays, projeté une fois pour
// toutes (projection Equal Earth, aires respectées), et un point d'ancrage par
// pays pour poser les origines des attaques sur la carte.
//
// Sources, lues sur le disque (aucun téléchargement ici) :
//   - world-atlas 2.0.2 (ISC), countries-110m.json : les contours de Natural
//     Earth au 1:110 000 000, domaine public ;
//   - la table des codes ISO 3166 (alpha-2 ↔ numérique) de i18n-iso-countries
//     7.14.0 (MIT), codes.json.
//
//   node outils/carte-monde.mjs <countries-110m.json> <codes.json> > web/carte-monde.js
import fs from 'node:fs';

const [, , cheminTopo, cheminCodes] = process.argv;
if (!cheminTopo || !cheminCodes) { console.error('usage : node outils/carte-monde.mjs <countries-110m.json> <codes.json>'); process.exit(2); }
const topo = JSON.parse(fs.readFileSync(cheminTopo, 'utf8'));
const numerique = Object.fromEntries(JSON.parse(fs.readFileSync(cheminCodes, 'utf8')).map(([a2, , n]) => [n, a2]));
// Territoires sans code ISO numérique dans Natural Earth : rattachés à un code.
const SANS_ID = { 'Kosovo': 'XK', 'N. Cyprus': 'CY', 'Somaliland': 'SO' };

const L = 1000;                          // largeur de la carte, en unités du viewBox
const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
function equalEarth(lon, lat) {
  const l = lon * Math.PI / 180, t = Math.asin(M * Math.sin(lat * Math.PI / 180));
  const t2 = t * t, t6 = t2 * t2 * t2;
  return [2 * Math.sqrt(3) * l * Math.cos(t) / (3 * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2))), t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))];
}
const [xMax] = equalEarth(180, 0);
const [, yMax] = equalEarth(0, 90);
const ECHELLE = L / (2 * xMax);
const HAUT_BRUT = 2 * yMax * ECHELLE;
// La carte coupe sous −60° (l'Antarctique n'est pas dessiné) : moins de vide en bas.
const [, yCoupe] = equalEarth(0, -60);
const H = Math.round(HAUT_BRUT / 2 - yCoupe * ECHELLE + 4);
const projeter = (lon, lat) => { const [x, y] = equalEarth(lon, lat); return [L / 2 + x * ECHELLE, HAUT_BRUT / 2 - y * ECHELLE]; };

// Les arcs de TopoJSON : décalages cumulés, puis la transformation du fichier.
const { scale: [sx, sy], translate: [tx, ty] } = topo.transform;
const arcs = topo.arcs.map(a => { let x = 0, y = 0; return a.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; }); });
const arc = i => (i >= 0 ? arcs[i] : arcs[~i].slice().reverse());
// Un anneau qui passe l'antiméridien (Russie, Fidji) est déroulé d'un seul
// côté : la carte le coupe au bord au lieu de tirer un trait d'un bord à l'autre.
function derouler(pts) {
  if (!pts.some((p, k) => k && Math.abs(p[0] - pts[k - 1][0]) > 180)) return pts;
  const est = pts.reduce((s, p) => s + p[0], 0) / pts.length > 0;
  return pts.map(([lon, lat]) => [est ? (lon < 0 ? lon + 360 : lon) : (lon > 0 ? lon - 360 : lon), lat]);
}
const anneau = ids => derouler(ids.flatMap((i, k) => (k ? arc(i).slice(1) : arc(i))));

const r1 = v => Math.round(v * 10) / 10;
function chemin(anneaux) {
  return anneaux.map(a => {
    const pts = a.map(([lon, lat]) => projeter(lon, lat));
    let d = '', px = null, py = null;
    for (const [x, y] of pts) {
      const X = r1(x), Y = r1(y);
      if (X === px && Y === py) continue;
      d += (d ? 'L' : 'M') + X + ' ' + Y;
      px = X; py = Y;
    }
    return d + 'Z';
  }).join('');
}
// Centre de gravité de l'anneau extérieur le plus grand : la France métropolitaine, pas la Guyane.
function centre(polys) {
  let meilleur = null;
  for (const p of polys) {
    const pts = p[0].map(([lon, lat]) => projeter(lon, lat));
    let a = 0, cx = 0, cy = 0;
    for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
      const f = pts[j][0] * pts[i][1] - pts[i][0] * pts[j][1];
      a += f; cx += (pts[j][0] + pts[i][0]) * f; cy += (pts[j][1] + pts[i][1]) * f;
    }
    if (!a) continue;
    if (!meilleur || Math.abs(a) > meilleur.a) meilleur = { a: Math.abs(a), x: cx / (3 * a), y: cy / (3 * a) };
  }
  return meilleur ? [r1(meilleur.x), r1(meilleur.y)] : null;
}

const pays = {}, centres = {};
for (const g of topo.objects.countries.geometries) {
  const a2 = numerique[g.id] || SANS_ID[g.properties?.name];
  if (!a2 || a2 === 'AQ') continue;
  const polys = g.type === 'Polygon' ? [g.arcs.map(anneau)] : g.arcs.map(p => p.map(anneau));
  pays[a2] = (pays[a2] || '') + chemin(polys.flat());
  if (!centres[a2]) centres[a2] = centre(polys);
}
// Pays et territoires trop petits pour le 1:110 000 000, d'où partent pourtant
// beaucoup de connexions : un point d'ancrage à leurs coordonnées.
const PETITS = {
  SG: [103.82, 1.35], HK: [114.17, 22.32], MO: [113.55, 22.2], BH: [50.55, 26.07], MT: [14.45, 35.9],
  MU: [57.55, -20.2], SC: [55.49, -4.68], MV: [73.2, 3.2], AD: [1.52, 42.51], MC: [7.42, 43.74],
  LI: [9.55, 47.16], SM: [12.46, 43.94], GI: [-5.35, 36.14], BB: [-59.54, 13.19], CW: [-68.99, 12.17],
  AW: [-69.97, 12.52], BM: [-64.78, 32.3], KY: [-81.25, 19.3], GU: [144.79, 13.44], IM: [-4.55, 54.24],
  JE: [-2.13, 49.21], GG: [-2.58, 49.45], FO: [-6.8, 62.0], KM: [43.3, -11.6], CV: [-23.6, 15.1],
  WS: [-172.1, -13.76], TO: [-175.2, -21.18], LC: [-60.98, 13.91], GD: [-61.68, 12.12], AG: [-61.8, 17.07],
  KN: [-62.75, 17.34], DM: [-61.37, 15.41], VC: [-61.2, 13.25], SX: [-63.05, 18.04], VG: [-64.62, 18.42],
  ST: [6.61, 0.19], PW: [134.58, 7.51], FM: [158.22, 6.92], MH: [171.18, 7.13], KI: [173.0, 1.42],
};
for (const [a2, [lon, lat]] of Object.entries(PETITS)) if (!centres[a2]) centres[a2] = projeter(lon, lat).map(r1);

const tri = o => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
process.stdout.write(`// Fabriqué par outils/carte-monde.mjs — ne pas modifier à la main.
// Contours : Natural Earth 1:110m (domaine public), via world-atlas 2.0.2 (ISC).
// Projection Equal Earth, ${L} × ${H} ; l'Antarctique n'est pas dessiné.
export const LARGEUR = ${L};
export const HAUTEUR = ${H};
export const PAYS = ${JSON.stringify(tri(pays))};
export const CENTRES = ${JSON.stringify(tri(centres))};
`);
