// Le pays d'une adresse, sans service extérieur ni base sous licence : les cinq
// registres régionaux d'Internet (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC)
// publient chaque jour la liste des blocs qu'ils ont attribués, avec le pays du
// titulaire. Téléchargées une fois par semaine, gardées sur le volume, elles
// donnent le pays d'enregistrement d'un réseau — pas l'emplacement exact d'une
// machine, mais assez pour dire d'où viennent les attaques.
import fs from 'node:fs';
import path from 'node:path';
import { versEntier, estPublique } from './ip.js';
import { lireBorne } from '../lecture.js';

export const REGISTRES = {
  arin: 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
  ripencc: 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest',
  apnic: 'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
  lacnic: 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
  afrinic: 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest',
};
const TAILLE_MAX = 80 * 1024 * 1024;
const JOURS = 7;
const PAYS = /^[A-Z]{2}$/;

/**
 * Les blocs attribués d'un fichier « delegated » :
 *   registre|pays|ipv4|début|nombre d'adresses|date|statut[|…]
 *   registre|pays|ipv6|début|longueur du préfixe|date|statut[|…]
 * Les lignes d'en-tête, de résumé et les blocs libres ou réservés sont écartés.
 */
export function lireDelegue(texte, sortie = { 4: [], 6: [] }) {
  let debutLigne = 0;
  while (debutLigne < texte.length) {
    let fin = texte.indexOf('\n', debutLigne);
    if (fin < 0) fin = texte.length;
    const l = texte.slice(debutLigne, fin);
    debutLigne = fin + 1;
    if (l.charCodeAt(0) === 35) continue;                        // « # »
    const c = l.split('|');
    if (c.length < 7 || (c[6] !== 'allocated' && c[6] !== 'assigned')) continue;
    const cc = c[1];
    if (!PAYS.test(cc) || cc === 'ZZ') continue;
    if (c[2] === 'ipv4') {
      const e = versEntier(c[3]), n = Number(c[4]);
      if (!e || e.v !== 4 || !Number.isInteger(n) || n < 1 || e.n + n - 1 > 0xffffffff) continue;
      sortie[4].push([e.n, e.n + n - 1, cc]);
    } else if (c[2] === 'ipv6') {
      const e = versEntier(c[3]), bits = Number(c[4]);
      if (!e || e.v !== 6 || !Number.isInteger(bits) || bits < 1 || bits > 128) continue;
      const libres = BigInt(128 - bits);
      const d = (e.n >> libres) << libres;
      sortie[6].push([d, d + (1n << libres) - 1n, cc]);
    }
  }
  return sortie;
}

/** Une table triée qui répond par dichotomie ; les blocs qui se chevauchent gardent le plus précis (le plus tardif à commencer). */
export class TablePays {
  constructor({ 4: v4 = [], 6: v6 = [] } = {}) {
    const codes = [], index = new Map();
    const code = cc => { let i = index.get(cc); if (i === undefined) { i = codes.length; codes.push(cc); index.set(cc, i); } return i; };
    v4.sort((a, b) => a[0] - b[0]);
    this.debut4 = new Float64Array(v4.length); this.fin4 = new Float64Array(v4.length); this.cc4 = new Uint16Array(v4.length);
    v4.forEach(([d, f, cc], i) => { this.debut4[i] = d; this.fin4[i] = f; this.cc4[i] = code(cc); });
    v6.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    this.debut6 = v6.map(x => x[0]); this.fin6 = v6.map(x => x[1]); this.cc6 = Uint16Array.from(v6, x => code(x[2]));
    this.codes = codes;
    this.taille = v4.length + v6.length;
  }
  pays(ip) {
    const e = versEntier(String(ip || ''));
    if (!e) return null;
    const [debut, fin, cc] = e.v === 4 ? [this.debut4, this.fin4, this.cc4] : [this.debut6, this.fin6, this.cc6];
    let bas = 0, haut = debut.length - 1, trouve = -1;
    while (bas <= haut) {
      const m = (bas + haut) >> 1;
      if (debut[m] <= e.n) { trouve = m; bas = m + 1; } else haut = m - 1;
    }
    // Un bloc plus large peut commencer avant et couvrir l'adresse : quelques pas en arrière suffisent.
    for (let i = trouve, k = 0; i >= 0 && k < 8; i--, k++) if (debut[i] <= e.n && e.n <= fin[i]) return this.codes[cc[i]];
    return null;
  }
}

export class Geo {
  constructor({ dossier, fetch: f = globalThis.fetch, maintenant = () => Date.now(), log = console }) {
    Object.assign(this, { dossier: path.join(dossier, 'geo'), fetch: f, maintenant, log });
    fs.mkdirSync(this.dossier, { recursive: true, mode: 0o700 });
    this.table = new TablePays();
    this.etat = { maj: null, erreurs: {}, blocs: 0 };
    this.cache = new Map();
    this.charger();
  }
  fichier(id) { return path.join(this.dossier, `${id}.txt`); }

  /** Relit les fichiers du volume et refait la table. */
  charger() {
    const blocs = { 4: [], 6: [] };
    let plusVieux = null;
    for (const id of Object.keys(REGISTRES)) {
      let texte;
      try { texte = fs.readFileSync(this.fichier(id), 'latin1'); } catch { continue; }
      lireDelegue(texte, blocs);
      const m = fs.statSync(this.fichier(id)).mtimeMs;
      plusVieux = plusVieux === null ? m : Math.min(plusVieux, m);
    }
    this.table = new TablePays(blocs);
    this.cache.clear();
    this.etat.blocs = this.table.taille;
    this.etat.maj = plusVieux;
    return this.table.taille;
  }

  /** Télécharge ce qui a plus d'une semaine (ou tout, si forcer) ; la table n'est refaite qu'une fois à la fin. */
  async actualiser({ forcer = false } = {}) {
    let nouveaux = 0;
    for (const [id, url] of Object.entries(REGISTRES)) {
      let age = Infinity;
      try { age = this.maintenant() - fs.statSync(this.fichier(id)).mtimeMs; } catch { /* absent */ }
      if (!forcer && age < JOURS * 86400e3) continue;
      try {
        const r = await this.fetch(url, { signal: AbortSignal.timeout(180_000), headers: { 'User-Agent': 'VIGIE (defensive network monitor)' } });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const texte = (await lireBorne(r, TAILLE_MAX)).toString('latin1');
        // Un fichier vide ou tronqué ne remplace pas le bon de la semaine passée.
        if (lireDelegue(texte)[4].length < 100) throw new Error('fichier sans blocs');
        const tmp = `${this.fichier(id)}.part`;
        fs.writeFileSync(tmp, texte, { mode: 0o600 });
        fs.renameSync(tmp, this.fichier(id));
        delete this.etat.erreurs[id];
        nouveaux++;
      } catch (e) {
        this.etat.erreurs[id] = e.message;
        this.log.warn?.(`[géo] ${id} : ${e.message}`);
      }
    }
    if (nouveaux) this.charger();
    return nouveaux;
  }

  /** « FR », « US »… ou null (adresse privée, inconnue, ou registres pas encore téléchargés). */
  pays(ip) {
    if (!ip || !estPublique(ip)) return null;
    let p = this.cache.get(ip);
    if (p !== undefined) return p;
    p = this.table.pays(ip);
    if (this.cache.size >= 20_000) this.cache.clear();
    this.cache.set(ip, p);
    return p;
  }

  public() { return { blocs: this.etat.blocs, maj: this.etat.maj, erreurs: { ...this.etat.erreurs }, registres: Object.keys(REGISTRES) }; }
}
