// Le carnet des attaques : ce qui frappe le réseau depuis l'extérieur, compté
// par heure, par adresse, par cible, par port et par nature. C'est lui qui
// nourrit l'accueil et la carte : d'où viennent les attaques, qui elles visent,
// combien VIGIE en a arrêté.
//
// Des millions de lignes de journaux par jour ne deviennent pas des millions
// d'écritures : chaque observation incrémente un compteur en mémoire, versé en
// base toutes les dix secondes dans une seule transaction. Une heure garde une
// ligne par (adresse, cible, port, nature), quel que soit le nombre de coups.
import { estPublique } from './ip.js';

export const NATURES = ['intrusion', 'pare-feu', 'force-brute', 'web', 'autre'];
const TAMPON_MAX = 50_000;
const HEURE = 3600e3;

/** La nature d'une observation du bouclier qui vient de l'extérieur. */
export function natureObservation(o) {
  if (o.type === 'ips') return 'intrusion';
  if (o.type === 'pare-feu' || o.type === 'flux') return 'pare-feu';
  return null;
}
/** La nature d'une alerte de la sentinelle, d'après ses groupes. */
export function natureAlerte(groupes = []) {
  if (groupes.includes('force-brute') || groupes.includes('auth-echec') || groupes.includes('utilisateur-invalide')) return 'force-brute';
  if (groupes.includes('web-attaque') || groupes.includes('web')) return 'web';
  if (groupes.includes('balayage') || groupes.includes('deni-de-service')) return 'pare-feu';
  return 'autre';
}

export class Carnet {
  constructor({ db, geo = null, bloquees = () => new Set(), maintenant = () => Date.now(), log = console }) {
    Object.assign(this, { db, geo, bloquees, maintenant, log });
    db.exec(`
      CREATE TABLE IF NOT EXISTS attaques(
        heure INTEGER NOT NULL, ip TEXT NOT NULL, cible TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 0,
        nature TEXT NOT NULL, pays TEXT, n INTEGER NOT NULL,
        PRIMARY KEY(heure, ip, cible, port, nature)) WITHOUT ROWID;
    `);
    this.ecrire = db.prepare(`INSERT INTO attaques(heure, ip, cible, port, nature, pays, n) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(heure, ip, cible, port, nature) DO UPDATE SET n = n + excluded.n, pays = COALESCE(attaques.pays, excluded.pays)`);
    this.tampon = new Map();
    this.cache = new Map();
    this.compte = 0;
  }

  /** Une attaque vue : une adresse publique qui frappe une cible du réseau. */
  noter({ quand, ip, cible = '', port = 0, nature }) {
    if (!ip || !NATURES.includes(nature) || !estPublique(ip)) return false;
    const h = Math.floor((quand || this.maintenant()) / HEURE) * HEURE;
    const cle = `${h}\u0001${ip}\u0001${String(cible || '').slice(0, 120)}\u0001${(Number(port) >>> 0) & 0xffff}\u0001${nature}`;
    this.tampon.set(cle, (this.tampon.get(cle) || 0) + 1);
    this.compte++;
    if (this.tampon.size >= TAMPON_MAX) this.vider();
    return true;
  }

  /** Verse le tampon en base, en une transaction. */
  vider() {
    if (!this.tampon.size) return 0;
    const lignes = this.tampon;
    this.tampon = new Map();
    this.db.exec('BEGIN');
    try {
      for (const [cle, n] of lignes) {
        const [h, ip, cible, port, nature] = cle.split('\u0001');
        this.ecrire.run(Number(h), ip, cible, Number(port), nature, this.geo?.pays(ip) ?? null, n);
      }
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      this.log.warn?.(`[carnet] ${e.message}`);
      return 0;
    }
    this.cache.clear();
    return lignes.size;
  }

  purger(jours = 30) {
    this.vider();
    const r = this.db.prepare('DELETE FROM attaques WHERE heure < ?').run(this.maintenant() - jours * 86400e3);
    return Number(r.changes);
  }

  /**
   * Le bilan d'une période : totaux, origines par pays, cibles, natures,
   * courbe par heure, sources les plus actives, et les liaisons pays → cible
   * pour dessiner la carte. Les lectures en base sont gardées quinze
   * secondes ; ce qui est bloqué est relu à chaque appel, pour qu'un blocage
   * se voie tout de suite.
   */
  resume({ heures = 24, top = 8 } = {}) {
    const t = this.maintenant();
    const depuis = Math.floor((t - heures * HEURE) / HEURE) * HEURE;
    // Ce qui attend dans le tampon est versé d'abord : s'il y en avait, le cache est vidé.
    this.vider();
    const cleCache = `${heures}|${top}|${Math.floor(t / 15e3)}`;
    let base = this.cache.get(cleCache);
    if (!base) {
      base = this.lire(depuis, t, top);
      this.cache.set(cleCache, base);
      if (this.cache.size > 20) this.cache.delete(this.cache.keys().next().value);
    }
    // Les adresses bloquées (pour de vrai ou en simulation) pendant la période.
    const arretees = this.bloquees(depuis);
    const parPays = new Map();
    let bloquees = 0;
    for (const r of base.parIp) {
      const b = arretees.has(r.ip);
      if (b) bloquees++;
      const x = parPays.get(r.pays) || { pays: r.pays, n: 0, sources: 0, bloquees: 0 };
      x.n += r.n; x.sources++; if (b) x.bloquees++;
      parPays.set(r.pays, x);
    }
    return {
      heures, depuis, total: base.total, sources: base.parIp.length, bloquees,
      pays: [...parPays.values()].sort((a, b) => b.n - a.n),
      cibles: base.cibles, natures: base.natures, ports: base.ports, parHeure: base.parHeure, liens: base.liens,
      top: base.top.map(r => ({ ...r, bloquee: arretees.has(r.ip) })),
    };
  }

  /** Les lectures en base d'un bilan, sans ce qui dépend des blocages. */
  lire(depuis, t, top) {
    const parIp = this.db.prepare(`SELECT ip, MAX(pays) AS pays, SUM(n) AS n, MAX(heure) AS derniere, GROUP_CONCAT(DISTINCT nature) AS natures
      FROM attaques WHERE heure >= ? GROUP BY ip`).all(depuis);
    const paysDe = new Map();
    const totalPays = new Map();
    let total = 0;
    for (const r of parIp) {
      r.pays = r.pays || this.geo?.pays(r.ip) || '??';
      paysDe.set(r.ip, r.pays);
      totalPays.set(r.pays, (totalPays.get(r.pays) || 0) + r.n);
      total += r.n;
    }
    const cibles = this.db.prepare(`SELECT cible, SUM(n) AS n, COUNT(DISTINCT ip) AS sources, GROUP_CONCAT(DISTINCT nature) AS natures
      FROM attaques WHERE heure >= ? AND cible != '' GROUP BY cible ORDER BY n DESC LIMIT 50`).all(depuis)
      .map(r => ({ cible: r.cible, n: r.n, sources: r.sources, natures: r.natures.split(',') }));
    const natures = this.db.prepare('SELECT nature, SUM(n) AS n, COUNT(DISTINCT ip) AS sources FROM attaques WHERE heure >= ? GROUP BY nature ORDER BY n DESC').all(depuis);
    const ports = this.db.prepare('SELECT port, SUM(n) AS n, COUNT(DISTINCT ip) AS sources FROM attaques WHERE heure >= ? AND port > 0 GROUP BY port ORDER BY n DESC LIMIT 10').all(depuis);
    const courbe = new Map(this.db.prepare('SELECT heure, SUM(n) AS n FROM attaques WHERE heure >= ? GROUP BY heure').all(depuis).map(r => [r.heure, r.n]));
    const parHeure = [];
    for (let h = depuis; h <= t; h += HEURE) parHeure.push({ heure: h, n: courbe.get(h) || 0 });
    const topIp = [...parIp].sort((a, b) => b.n - a.n).slice(0, 50)
      .map(r => ({ ip: r.ip, pays: r.pays, n: r.n, derniere: r.derniere, natures: r.natures.split(',') }));

    // Les liaisons de la carte : les pays les plus actifs vers les cibles les plus visées.
    const topPays = new Set([...totalPays].sort((a, b) => b[1] - a[1]).slice(0, top).map(x => x[0]));
    const topCibles = new Set(cibles.slice(0, 6).map(x => x.cible));
    const liens = new Map();
    for (const r of this.db.prepare(`SELECT ip, cible, SUM(n) AS n FROM attaques WHERE heure >= ? AND cible != '' GROUP BY ip, cible LIMIT 200000`).iterate(depuis)) {
      const p = paysDe.get(r.ip);
      if (!topPays.has(p) || !topCibles.has(r.cible)) continue;
      const k = `${p}\u0001${r.cible}`;
      liens.set(k, (liens.get(k) || 0) + r.n);
    }
    return {
      total, parIp: parIp.map(r => ({ ip: r.ip, pays: r.pays, n: r.n })), cibles, natures, ports, parHeure, top: topIp,
      liens: [...liens].map(([k, n]) => { const [p, c] = k.split('\u0001'); return { pays: p, cible: c, n }; }).sort((a, b) => b.n - a.n),
    };
  }
}
