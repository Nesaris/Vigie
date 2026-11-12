// L'origine des attaques : pays d'une adresse d'après les registres, et
// carnet des attaques compté par heure.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { lireDelegue, TablePays, Geo, REGISTRES } from '../src/bouclier/geo.js';
import { Carnet, natureAlerte, natureObservation } from '../src/bouclier/carnet.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'carte-'));
const silence = { info() {}, warn() {}, error() {} };

// Un extrait au format des registres (adresses de documentation et blocs réels d'exemple).
const DELEGUE = [
  '2|ripencc|20261111|5|19830705|20261111|+0100',
  'ripencc|*|ipv4|*|3|summary',
  'ripencc|FR|ipv4|2.0.0.0|1048576|20100712|allocated|a',
  'ripencc|DE|ipv4|5.0.0.0|65536|20100712|allocated|b',
  'ripencc|NL|ipv4|5.0.0.0|256|20100712|assigned|c',
  'ripencc||ipv4|5.1.0.0|256||available|',
  'ripencc|ZZ|ipv4|5.2.0.0|256||reserved|',
  'ripencc|SE|ipv6|2001:6b0::|32|20000303|allocated|d',
  '# un commentaire',
  'ripencc|GB|ipv4|81.2.69.0|256|20100712|assigned|e',
].join('\n');

test('registres : blocs attribués lus, libres et réservés écartés', () => {
  const b = lireDelegue(DELEGUE);
  assert.equal(b[4].length, 4);
  assert.equal(b[6].length, 1);
  assert.deepEqual(b[4].map(x => x[2]), ['FR', 'DE', 'NL', 'GB']);
  const t = new TablePays(b);
  assert.equal(t.pays('2.15.3.4'), 'FR');
  assert.equal(t.pays('2.16.0.0'), null);          // juste après le bloc
  assert.equal(t.pays('5.0.0.9'), 'NL');           // le bloc le plus précis l'emporte
  assert.equal(t.pays('5.0.200.1'), 'DE');
  assert.equal(t.pays('5.1.0.1'), null);           // libre
  assert.equal(t.pays('2001:6b0:1::5'), 'SE');
  assert.equal(t.pays('2001:6b1::1'), null);
  assert.equal(t.pays('pas une adresse'), null);
});

test('géo : fichiers du volume relus, téléchargement mis de côté s’il est vide, adresses privées sans pays', async () => {
  const dossier = path.join(tmp, 'geo1');
  const appels = [];
  const lignes = Array.from({ length: 150 }, (_, i) => `arin|US|ipv4|${20 + Math.floor(i / 250)}.${i % 250}.0.0|65536|20100101|allocated|x`).join('\n');
  const fetch = async url => { appels.push(url); return new Response(url.includes('arin') ? lignes : 'vide\n'); };
  const g = new Geo({ dossier, fetch, log: silence });
  assert.equal(g.pays('20.3.4.5'), null);
  const n = await g.actualiser();
  assert.equal(n, 1);                                   // seul ARIN avait des blocs
  assert.equal(appels.length, Object.keys(REGISTRES).length);
  assert.equal(g.pays('20.3.4.5'), 'US');
  assert.equal(g.pays('192.168.1.10'), null);
  assert.ok(g.public().erreurs.ripencc);
  // Une semaine ne s'est pas écoulée : ARIN n'est pas redemandé.
  appels.length = 0;
  await g.actualiser();
  assert.ok(!appels.some(u => u.includes('arin')));
  // Un redémarrage relit le volume.
  assert.equal(new Geo({ dossier, fetch, log: silence }).pays('20.3.4.5'), 'US');
});

test('carnet : coups comptés par heure, tampon versé en une fois, bilan par pays et par cible', () => {
  const db = new DatabaseSync(':memory:');
  let t = Date.UTC(2026, 10, 12, 10, 30);
  const geo = { pays: ip => ({ '45.155.205.10': 'CN', '45.155.205.11': 'CN', '91.240.118.3': 'RU' })[ip] ?? null };
  const c = new Carnet({ db, geo, maintenant: () => t, log: silence, bloquees: () => new Set(['45.155.205.10']) });
  for (let i = 0; i < 1000; i++) c.noter({ quand: t, ip: '45.155.205.10', cible: '10.0.5.20', port: 22, nature: 'force-brute' });
  for (let i = 0; i < 10; i++) c.noter({ quand: t, ip: '45.155.205.11', cible: '10.0.5.20', port: 443, nature: 'web' });
  c.noter({ quand: t - 3600e3, ip: '91.240.118.3', cible: 'nas', port: 0, nature: 'intrusion' });
  assert.equal(c.noter({ quand: t, ip: '10.0.0.4', cible: 'nas', nature: 'intrusion' }), false);   // pas une adresse publique
  assert.equal(c.noter({ quand: t, ip: '91.240.118.3', nature: 'inconnue' }), false);
  assert.equal(c.vider(), 3);                                 // trois lignes pour 1 011 coups
  assert.equal(db.prepare('SELECT SUM(n) AS n FROM attaques').get().n, 1011);
  const r = c.resume({ heures: 24 });
  assert.equal(r.total, 1011);
  assert.equal(r.sources, 3);
  assert.equal(r.bloquees, 1);
  assert.deepEqual(r.pays.map(p => [p.pays, p.n, p.sources, p.bloquees]), [['CN', 1010, 2, 1], ['RU', 1, 1, 0]]);
  assert.deepEqual(r.cibles.map(x => [x.cible, x.n, x.sources]), [['10.0.5.20', 1010, 2], ['nas', 1, 1]]);
  assert.equal(r.ports[0].port, 22);
  assert.equal(r.top[0].ip, '45.155.205.10');
  assert.equal(r.top[0].bloquee, true);
  assert.equal(r.parHeure.length, 25);
  assert.equal(r.parHeure.at(-1).n, 1010);
  assert.deepEqual(r.liens[0], { pays: 'CN', cible: '10.0.5.20', n: 1010 });
  // Après trente jours, la purge retire l'heure.
  t += 31 * 86400e3;
  assert.equal(c.purger(30), 3);
});

test('carnet : natures des observations et des alertes', () => {
  assert.equal(natureObservation({ type: 'ips' }), 'intrusion');
  assert.equal(natureObservation({ type: 'pare-feu' }), 'pare-feu');
  assert.equal(natureObservation({ type: 'dns' }), null);
  assert.equal(natureAlerte(['ssh', 'auth-echec']), 'force-brute');
  assert.equal(natureAlerte(['web', 'web-attaque']), 'web');
  assert.equal(natureAlerte(['noyau']), 'autre');
});
