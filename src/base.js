// Base de VIGIE : audits et leurs constats, événements de la veille, actions
// de remédiation (avec l'état d'avant, pour les défaire), compteurs de l'IA et
// réglages. Les secrets des réglages (clé d'IA en nuage, jeton docker-control)
// sont scellés par le Coffre du socle : la base seule ne les rend pas.
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const REF = /^[A-Za-z0-9_-]{12}$/;
export const nouvelleRef = () => crypto.randomBytes(9).toString('base64url');

export const GRAVITES = ['safe', 'info', 'faible', 'eleve', 'critique'];
export const RANG = Object.fromEntries(GRAVITES.map((g, i) => [g, i]));
// Les types d'appareils que la réaction rapide peut isoler par défaut : jamais
// l'infrastructure (routeur, pare-feu, commutateur, serveur, NAS, hyperviseur).
export const TYPES_ISOLABLES = ['unknown', 'iot', 'sensor', 'phone', 'tablet', 'pc', 'computer', 'laptop', 'camera', 'tv', 'console', 'voip', 'printer'];
export const TYPES_PROTEGES = ['router', 'firewall', 'switch', 'ap', 'server', 'nas', 'hypervisor', 'docker', 'vm', 'container'];

const MAX_AUDITS = 200;
const MAX_EVENEMENTS = 5000;
// Qui a isolé, rendu ou balayé quel appareil : gardé un an, comme le journal de sécurité.
const ACTIONS_JOURS = 365;

export function ouvrirBase(dossier) {
  fs.mkdirSync(dossier, { recursive: true, mode: 0o700 });
  const fichier = path.join(dossier, 'vigie.db');
  fs.closeSync(fs.openSync(fichier, 'a', 0o600));
  for (const f of [fichier, fichier + '-wal', fichier + '-shm']) if (fs.existsSync(f)) fs.chmodSync(f, 0o600);
  const db = new DatabaseSync(fichier);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS audits(
      id TEXT PRIMARY KEY, debut INTEGER NOT NULL, fin INTEGER, statut TEXT NOT NULL,
      declencheur TEXT NOT NULL, auteur TEXT NOT NULL DEFAULT '',
      score INTEGER, domaines TEXT NOT NULL DEFAULT '{}', distribution TEXT NOT NULL DEFAULT '{}',
      sources TEXT NOT NULL DEFAULT '{}', ia TEXT NOT NULL DEFAULT '{}', erreur TEXT);
    CREATE TABLE IF NOT EXISTS constats(
      id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
      cle TEXT NOT NULL, regle TEXT NOT NULL, ref TEXT NOT NULL, domaine TEXT NOT NULL,
      gravite TEXT NOT NULL, titre TEXT NOT NULL, sujet TEXT NOT NULL DEFAULT '', sujet_id TEXT,
      preuve TEXT NOT NULL DEFAULT '{}', correction TEXT NOT NULL DEFAULT '', action TEXT,
      ia_statut TEXT, ia_note TEXT);
    CREATE INDEX IF NOT EXISTS constats_audit ON constats(audit_id);
    CREATE TABLE IF NOT EXISTS evenements(
      id TEXT PRIMARY KEY, quand INTEGER NOT NULL, gravite TEXT NOT NULL, type TEXT NOT NULL,
      titre TEXT NOT NULL, texte TEXT NOT NULL DEFAULT '', sujet TEXT NOT NULL DEFAULT '',
      cle TEXT NOT NULL DEFAULT '', acquitte INTEGER, acquitte_par TEXT);
    CREATE INDEX IF NOT EXISTS evenements_quand ON evenements(quand);
    CREATE TABLE IF NOT EXISTS actions(
      id TEXT PRIMARY KEY, quand INTEGER NOT NULL, type TEXT NOT NULL, cible TEXT NOT NULL,
      cible_nom TEXT NOT NULL DEFAULT '', auteur TEXT NOT NULL, motif TEXT NOT NULL DEFAULT '',
      automatique INTEGER NOT NULL DEFAULT 0, etat TEXT NOT NULL, avant TEXT NOT NULL DEFAULT '{}',
      resultat TEXT NOT NULL DEFAULT '', annulee_par TEXT, annulee_le INTEGER);
    CREATE TABLE IF NOT EXISTS ia_usage(jour TEXT PRIMARY KEY, appels INTEGER NOT NULL, jetons INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS reglages(cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sentinelle_alertes(
      id TEXT PRIMARY KEY, quand INTEGER NOT NULL, hote TEXT NOT NULL DEFAULT '', programme TEXT NOT NULL DEFAULT '',
      regle TEXT NOT NULL, niveau INTEGER NOT NULL, groupes TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
      srcip TEXT NOT NULL DEFAULT '', utilisateur TEXT NOT NULL DEFAULT '', champs TEXT NOT NULL DEFAULT '{}', extrait TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS sentinelle_alertes_quand ON sentinelle_alertes(quand);
    CREATE INDEX IF NOT EXISTS sentinelle_alertes_hote ON sentinelle_alertes(hote, quand);
    CREATE TABLE IF NOT EXISTS sentinelle_vus(cle TEXT PRIMARY KEY, quand INTEGER NOT NULL);
  `);
  return db;
}

export const DEFAUTS = {
  // L'IA : aucune par défaut. Locale = l'Ollama que le Hub relie ; en nuage =
  // une clé à soi. « les-deux » : la locale relit, le nuage tranche et rédige ;
  // « secours » : la locale, et le nuage seulement si elle échoue.
  ia: { mode: 'aucune', fournisseur: 'anthropic', modeleCloud: '', modeleLocal: '', cle: null, appelsJour: 20, jetonsJour: 200000 },
  veille: { actif: true, minutes: 15, auditQuotidien: true, heure: 3, sondeTls: true },
  // Réaction rapide : coupée tant que l'administrateur ne l'a pas allumée.
  // seuil : score de danger (MapMyLAN) à partir duquel un appareil suspect est isolé.
  reaction: { actif: false, types: TYPES_ISOLABLES, parHeure: 3, seuil: 85 },
  docker: { jeton: null },
  // Adresses (IPv4 ou CIDR) que VIGIE ne sonde pas et sur lesquelles il n'agit jamais.
  perimetre: { exclus: [] },
  // Billetterie (Aselia ou autre) au format ticket/v1, et Telegram : à partir de quelle gravité.
  billetterie: { url: '', cle: null, entete: 'X-Ticket-Key', marqueur: 'ticket', seuil: 'eleve' },
  telegram: { jeton: null, chat: '', seuil: 'eleve' },
  // Le bouclier : capteurs, listes de menaces, corrélation, riposte (src/bouclier).
  // mode : observer (signale), simulation (note ce qu'il aurait bloqué), actif
  // (bloque seul les adresses extérieures au-delà du seuil).
  bouclier: {
    mode: 'actif', seuil: 100, seuilInterne: 100, demiVieMinutes: 60,
    balayagePorts: 15, balayageCibles: 12, forceBrute: 20,
    dureesMinutes: [60, 1440, 10080, 43200], autoParHeure: 100, maxUnifi: 1000,
    listes: {}, listesPropres: [], listesHeures: 6, listeBlanche: [], emetteurs: [], sondes: [],
    unifiHote: '', unifiPort: 443, unifiFp: '', cleUnifi: null, jetonListe: null,
    // Cloudflare, en amont : jeton d'API, compte, zones protégées, liste créée par VIGIE,
    // et le mode « Under Attack » automatique en tempête.
    cloudflareJeton: null, cloudflareCompte: '', cloudflareZones: [], cloudflareListe: '', cloudflareModeAttaque: false,
    // Tempête : sources distinctes sur un même port et lignes entrantes en une minute ;
    // blocages immédiats des plus bruyantes ; durée du mode Under Attack.
    tempeteSources: 40, tempeteLignes: 600, tempeteBlocages: 20, tempeteMinutes: 15,
    // Le carnet des attaques (accueil, carte) : jours gardés.
    carnetJours: 30,
  },
  // La sentinelle : l'analyse des journaux d'hôtes reçus en syslog (src/sentinelle).
  // seuil : niveau (0-15) à partir duquel une alerte est retenue ; seuilEvenement :
  // niveau à partir duquel elle devient un événement de VIGIE (diffusé) ;
  // correler : les alertes nourrissent le bouclier (score des adresses).
  sentinelle: { actif: true, seuil: 7, seuilEvenement: 10, correler: true, retentionJours: 30 },
};
export const SCELLES = { ia: ['cle'], docker: ['jeton'], billetterie: ['cle'], telegram: ['jeton'], bouclier: ['cleUnifi', 'jetonListe', 'cloudflareJeton'] };

const json = (s, defaut) => { try { return s ? JSON.parse(s) : defaut; } catch { return defaut; } };

export class Magasin {
  constructor(db, { coffre }) { this.db = db; this.coffre = coffre; }

  // Après une rotation de SOCLE_CLE (le socle a rescellé ses propres secrets) :
  // ceux de VIGIE, scellés sous l'ancienne clé, sont rescellés sous la neuve.
  //   - sans SOCLE_CLE_ANCIENNE posée, le démarrage s'arrête (la reposer le
  //     temps d'un démarrage suffit, rien n'est perdu) ;
  //   - avec elle, un secret illisible sous les deux clés est retiré et le
  //     bilan le dit : il se ressaisit dans les réglages.
  resceller() {
    const avant = this.coffre.precedente;
    const bilan = { rescelles: 0, retires: 0 };
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const [nom, champs] of Object.entries(SCELLES)) {
        const r = this.reglage(nom), maj = {};
        for (const champ of champs) {
          const scelle = r[champ];
          if (!scelle) continue;
          try { this.coffre.ouvre(`${nom}.${champ}`, scelle); continue; } catch { /* scellé sous une autre clé */ }
          if (!avant) throw new Error(`Un secret de VIGIE (${nom}) est illisible sous SOCLE_CLE : repose la clé remplacée dans SOCLE_CLE_ANCIENNE le temps d'un démarrage.`);
          try { maj[champ] = this.coffre.scelle(`${nom}.${champ}`, avant.ouvre(`${nom}.${champ}`, scelle)); bilan.rescelles++; } catch { maj[champ] = null; bilan.retires++; }
        }
        if (Object.keys(maj).length) this.poserReglage(nom, maj);
      }
      this.db.exec('COMMIT');
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
    return bilan;
  }

  // Les gestes d'un compte, nommé par son identifiant dans les audits, les
  // actions, les acquittements et les blocages : exportés à sa demande.
  donneesDe(identifiant) {
    const q = (sql, ...a) => this.db.prepare(sql).all(...a);
    return {
      audits: q('SELECT id, debut, declencheur FROM audits WHERE auteur = ? ORDER BY debut', identifiant),
      actions: q('SELECT id, quand, type, cible_nom, motif, etat, annulee_par, annulee_le FROM actions WHERE auteur = ? OR annulee_par = ? ORDER BY quand', identifiant, identifiant),
      acquittements: q('SELECT id, quand, titre, acquitte FROM evenements WHERE acquitte_par = ? ORDER BY quand', identifiant),
      blocages: q('SELECT id, ip, debut, motif, etat, leve_par, leve_le FROM blocages WHERE auteur = ? OR leve_par = ? ORDER BY debut', identifiant, identifiant),
    };
  }
  /**
   * À la suppression d'un compte, son identifiant disparaît des tables de
   * VIGIE dans la même transaction que la ligne du compte : un déclencheur de
   * la base, posé une fois toutes les tables créées.
   */
  poserOubli() {
    const neutre = "'compte supprimé'";
    const maj = [['audits', 'auteur'], ['actions', 'auteur'], ['actions', 'annulee_par'], ['evenements', 'acquitte_par'], ['blocages', 'auteur'], ['blocages', 'leve_par']]
      .map(([t, c]) => `UPDATE ${t} SET ${c} = ${neutre} WHERE ${c} = OLD.identifiant;`).join('\n      ');
    this.db.exec(`DROP TRIGGER IF EXISTS vigie_oubli;
    CREATE TRIGGER vigie_oubli BEFORE DELETE ON socle_comptes BEGIN
      ${maj}
    END;`);
  }

  // Réglages
  reglage(nom) {
    const l = this.db.prepare('SELECT valeur FROM reglages WHERE cle = ?').get(nom);
    return { ...DEFAUTS[nom], ...json(l?.valeur, {}) };
  }
  poserReglage(nom, valeur) {
    const fusion = { ...this.reglage(nom), ...valeur };
    this.db.prepare('INSERT INTO reglages(cle, valeur) VALUES(?, ?) ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur').run(nom, JSON.stringify(fusion));
    return fusion;
  }
  secret(nom, champ) {
    const s = this.reglage(nom)[champ];
    return s ? this.coffre.ouvre(`${nom}.${champ}`, s) : '';
  }
  poserSecret(nom, champ, clair) {
    this.poserReglage(nom, { [champ]: clair ? this.coffre.scelle(`${nom}.${champ}`, clair) : null });
  }
  /** Les réglages tels qu'une interface peut les lire : un secret dit seulement s'il est posé. */
  reglagePublic(nom) {
    const r = this.reglage(nom);
    for (const champ of SCELLES[nom] || []) r[champ] = !!r[champ];
    return r;
  }
  /** Un état interne (mémoire de la veille), hors des réglages publics. */
  memoire(nom, defaut = null) { return json(this.db.prepare('SELECT valeur FROM reglages WHERE cle = ?').get(`_${nom}`)?.valeur, defaut); }
  poserMemoire(nom, valeur) { this.db.prepare('INSERT INTO reglages(cle, valeur) VALUES(?, ?) ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur').run(`_${nom}`, JSON.stringify(valeur)); }

  // Audits
  ouvrirAudit({ declencheur, auteur = '' }) {
    const id = nouvelleRef();
    this.db.prepare("INSERT INTO audits(id, debut, statut, declencheur, auteur) VALUES(?, ?, 'en cours', ?, ?)").run(id, Date.now(), declencheur, auteur);
    return id;
  }
  enregistrerConstats(auditId, constats) {
    const ins = this.db.prepare(`INSERT INTO constats(id, audit_id, cle, regle, ref, domaine, gravite, titre, sujet, sujet_id, preuve, correction, action)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    this.db.exec('BEGIN');
    try {
      for (const c of constats) ins.run(nouvelleRef(), auditId, c.cle, c.regle, c.ref, c.domaine, c.gravite, c.titre.slice(0, 300), String(c.sujet || '').slice(0, 200),
        c.sujetId ?? null, JSON.stringify(c.preuve || {}), String(c.correction || '').slice(0, 4000), c.action ? JSON.stringify(c.action) : null);
      this.db.exec('COMMIT');
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  fermerAudit(id, { statut, score = null, domaines = {}, distribution = {}, sources = {}, erreur = null }) {
    this.db.prepare('UPDATE audits SET fin = ?, statut = ?, score = ?, domaines = ?, distribution = ?, sources = ?, erreur = ? WHERE id = ?')
      .run(Date.now(), statut, score, JSON.stringify(domaines), JSON.stringify(distribution), JSON.stringify(sources), erreur, id);
    // Les plus anciens partent : l'historique reste borné.
    this.db.prepare('DELETE FROM audits WHERE id NOT IN (SELECT id FROM audits ORDER BY debut DESC, rowid DESC LIMIT ?)').run(MAX_AUDITS);
  }
  poserIA(id, ia) { this.db.prepare('UPDATE audits SET ia = ? WHERE id = ?').run(JSON.stringify(ia), id); }
  /** Au démarrage : un audit ou une relecture qu'un arrêt a coupés ne restent pas « en cours » pour toujours. */
  reprendreInterrompus(maintenant = Date.now()) {
    const n = this.db.prepare("UPDATE audits SET statut = 'echec', fin = ?, erreur = 'interrompu par un redémarrage de VIGIE' WHERE statut = 'en cours'").run(maintenant).changes;
    let ia = 0;
    for (const a of this.db.prepare("SELECT id, ia FROM audits WHERE ia LIKE '%\"en cours\"%'").all()) {
      const v = json(a.ia, {});
      if (v.statut === 'en cours') { this.poserIA(a.id, { statut: 'ignoree', raison: 'relecture interrompue par un redémarrage' }); ia++; }
    }
    return { audits: n, relectures: ia };
  }
  verdictIA(constatId, statut, note) { this.db.prepare('UPDATE constats SET ia_statut = ?, ia_note = ? WHERE id = ?').run(statut, note, constatId); }

  ligneAudit(a) {
    return a && { id: a.id, debut: a.debut, fin: a.fin, statut: a.statut, declencheur: a.declencheur, auteur: a.auteur, score: a.score,
      domaines: json(a.domaines, {}), distribution: json(a.distribution, {}), sources: json(a.sources, {}), ia: json(a.ia, {}), erreur: a.erreur };
  }
  audit(id) { return this.ligneAudit(this.db.prepare('SELECT * FROM audits WHERE id = ?').get(id)); }
  dernierAudit() { return this.ligneAudit(this.db.prepare("SELECT * FROM audits WHERE statut = 'termine' ORDER BY debut DESC, rowid DESC LIMIT 1").get()); }
  auditEnCours() { return this.ligneAudit(this.db.prepare("SELECT * FROM audits WHERE statut = 'en cours' ORDER BY debut DESC, rowid DESC LIMIT 1").get()); }
  audits(limite = 50) { return this.db.prepare('SELECT * FROM audits ORDER BY debut DESC, rowid DESC LIMIT ?').all(limite).map(a => this.ligneAudit(a)); }
  /** Score et date des audits terminés, du plus ancien au plus récent : la tendance. */
  historique(limite = 60) {
    return this.db.prepare("SELECT debut, score FROM audits WHERE statut = 'termine' ORDER BY debut DESC, rowid DESC LIMIT ?").all(limite).reverse();
  }

  ligneConstat(c) {
    return c && { id: c.id, auditId: c.audit_id, cle: c.cle, regle: c.regle, ref: c.ref, domaine: c.domaine, gravite: c.gravite, titre: c.titre,
      sujet: c.sujet, sujetId: c.sujet_id, preuve: json(c.preuve, {}), correction: c.correction, action: json(c.action, null), ia: c.ia_statut ? { statut: c.ia_statut, note: c.ia_note } : null };
  }
  constats(auditId) {
    return this.db.prepare(`SELECT * FROM constats WHERE audit_id = ? ORDER BY CASE gravite WHEN 'critique' THEN 0 WHEN 'eleve' THEN 1 WHEN 'faible' THEN 2 WHEN 'info' THEN 3 ELSE 4 END, domaine, titre`).all(auditId).map(c => this.ligneConstat(c));
  }
  constat(id) { return this.ligneConstat(this.db.prepare('SELECT * FROM constats WHERE id = ?').get(id)); }

  // Événements de la veille
  evenement({ gravite, type, titre, texte = '', sujet = '', cle = '' }) {
    const id = nouvelleRef();
    this.db.prepare('INSERT INTO evenements(id, quand, gravite, type, titre, texte, sujet, cle) VALUES(?,?,?,?,?,?,?,?)')
      .run(id, Date.now(), gravite, type, titre.slice(0, 300), String(texte).slice(0, 2000), String(sujet).slice(0, 200), String(cle).slice(0, 300));
    this.db.prepare('DELETE FROM evenements WHERE id NOT IN (SELECT id FROM evenements ORDER BY quand DESC LIMIT ?)').run(MAX_EVENEMENTS);
    return id;
  }
  evenements({ limite = 100, depuis = 0 } = {}) {
    return this.db.prepare('SELECT * FROM evenements WHERE quand >= ? ORDER BY quand DESC LIMIT ?').all(depuis, limite)
      .map(e => ({ id: e.id, quand: e.quand, gravite: e.gravite, type: e.type, titre: e.titre, texte: e.texte, sujet: e.sujet, acquitte: e.acquitte || null, acquittePar: e.acquitte_par || null }));
  }
  acquitter(id, qui) {
    return this.db.prepare('UPDATE evenements SET acquitte = ?, acquitte_par = ? WHERE id = ? AND acquitte IS NULL').run(Date.now(), qui, id).changes > 0;
  }

  // Actions de remédiation
  noterAction({ type, cible, cibleNom = '', auteur, motif = '', automatique = false, etat, avant = {}, resultat = '' }) {
    const id = nouvelleRef();
    this.db.prepare('INSERT INTO actions(id, quand, type, cible, cible_nom, auteur, motif, automatique, etat, avant, resultat) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, Date.now(), type, cible, cibleNom, auteur, motif.slice(0, 300), automatique ? 1 : 0, etat, JSON.stringify(avant), String(resultat).slice(0, 1000));
    this.db.prepare('DELETE FROM actions WHERE quand < ?').run(Date.now() - ACTIONS_JOURS * 86400e3);
    return this.action(id);
  }
  ligneAction(a) {
    return a && { id: a.id, quand: a.quand, type: a.type, cible: a.cible, cibleNom: a.cible_nom, auteur: a.auteur, motif: a.motif, automatique: !!a.automatique,
      etat: a.etat, avant: json(a.avant, {}), resultat: a.resultat, annuleePar: a.annulee_par || null, annuleeLe: a.annulee_le || null };
  }
  action(id) { return this.ligneAction(this.db.prepare('SELECT * FROM actions WHERE id = ?').get(id)); }
  actions(limite = 100) { return this.db.prepare('SELECT * FROM actions ORDER BY quand DESC LIMIT ?').all(limite).map(a => this.ligneAction(a)); }
  annulerAction(id, qui, resultat) {
    this.db.prepare("UPDATE actions SET etat = 'annulee', annulee_par = ?, annulee_le = ?, resultat = ? WHERE id = ?").run(qui, Date.now(), String(resultat).slice(0, 1000), id);
    return this.action(id);
  }
  /** Les isolements automatiques de la dernière heure : la réaction rapide est bornée. */
  automatiquesRecentes(ms = 3600e3) { return this.db.prepare('SELECT COUNT(*) n FROM actions WHERE automatique = 1 AND quand > ?').get(Date.now() - ms).n; }

  // Sentinelle : alertes des journaux d'hôtes, mémoire « première fois »
  sentinelleAlerte(a) {
    const id = nouvelleRef();
    this.db.prepare('INSERT INTO sentinelle_alertes(id, quand, hote, programme, regle, niveau, groupes, description, srcip, utilisateur, champs, extrait) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, a.quand, String(a.hote || '').slice(0, 253), String(a.programme || '').slice(0, 64), a.regle, a.niveau, (a.groupes || []).join(','), String(a.description || '').slice(0, 300),
        String(a.champs?.srcip || '').slice(0, 45), String(a.champs?.utilisateur || '').slice(0, 64), JSON.stringify(a.champs || {}).slice(0, 2000), String(a.extrait || '').slice(0, 512));
    return id;
  }
  ligneSentinelle(l) {
    return l && { id: l.id, quand: l.quand, hote: l.hote, programme: l.programme, regle: l.regle, niveau: l.niveau, groupes: l.groupes ? l.groupes.split(',') : [], description: l.description,
      srcip: l.srcip, utilisateur: l.utilisateur, champs: json(l.champs, {}), extrait: l.extrait };
  }
  sentinelleAlertes({ limite = 100, depuis = 0, niveau = 0, hote = '', regle = '', srcip = '' } = {}) {
    const cond = ['quand >= ?', 'niveau >= ?'], args = [depuis, niveau];
    if (hote) { cond.push('hote = ?'); args.push(hote); }
    if (regle) { cond.push('regle = ?'); args.push(regle); }
    if (srcip) { cond.push('srcip = ?'); args.push(srcip); }
    return this.db.prepare(`SELECT * FROM sentinelle_alertes WHERE ${cond.join(' AND ')} ORDER BY quand DESC LIMIT ?`).all(...args, limite).map(l => this.ligneSentinelle(l));
  }
  /** Comptes par niveau et par hôte sur une période : le tableau de bord. */
  sentinelleBilan(depuis) {
    return {
      parNiveau: Object.fromEntries(this.db.prepare('SELECT niveau, COUNT(*) n FROM sentinelle_alertes WHERE quand >= ? GROUP BY niveau').all(depuis).map(x => [x.niveau, x.n])),
      parHote: this.db.prepare('SELECT hote, COUNT(*) n, MAX(niveau) niveau FROM sentinelle_alertes WHERE quand >= ? GROUP BY hote ORDER BY niveau DESC, n DESC LIMIT 100').all(depuis),
      parRegle: this.db.prepare('SELECT regle, COUNT(*) n, MAX(niveau) niveau FROM sentinelle_alertes WHERE quand >= ? GROUP BY regle ORDER BY n DESC LIMIT 60').all(depuis),
      parSource: this.db.prepare("SELECT srcip, COUNT(*) n, MAX(niveau) niveau FROM sentinelle_alertes WHERE quand >= ? AND srcip <> '' GROUP BY srcip ORDER BY niveau DESC, n DESC LIMIT 60").all(depuis),
      total: this.db.prepare('SELECT COUNT(*) n FROM sentinelle_alertes WHERE quand >= ?').get(depuis).n,
    };
  }
  sentinellePurger(jours) {
    const n = this.db.prepare('DELETE FROM sentinelle_alertes WHERE quand < ?').run(Date.now() - jours * 86400e3).changes;
    this.db.prepare('DELETE FROM sentinelle_vus WHERE quand < ?').run(Date.now() - 180 * 86400e3);
    return n;
  }
  sentinelleVu(cle) { return !!this.db.prepare('SELECT 1 FROM sentinelle_vus WHERE cle = ?').get(cle); }
  sentinelleNoterVu(cle) { this.db.prepare('INSERT INTO sentinelle_vus(cle, quand) VALUES(?, ?) ON CONFLICT(cle) DO UPDATE SET quand = excluded.quand').run(cle, Date.now()); }

  // Compteurs de l'IA (plafond quotidien)
  usageIA(jour = new Date().toISOString().slice(0, 10)) { return this.db.prepare('SELECT appels, jetons FROM ia_usage WHERE jour = ?').get(jour) || { appels: 0, jetons: 0 }; }
  compterIA(jetons, jour = new Date().toISOString().slice(0, 10)) {
    this.db.prepare('INSERT INTO ia_usage(jour, appels, jetons) VALUES(?, 1, ?) ON CONFLICT(jour) DO UPDATE SET appels = appels + 1, jetons = jetons + excluded.jetons').run(jour, Math.max(0, Math.round(jetons || 0)));
    this.db.prepare('DELETE FROM ia_usage WHERE jour < ?').run(new Date(Date.now() - 90 * 86400e3).toISOString().slice(0, 10));
  }
}
