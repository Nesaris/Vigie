// Routes de VIGIE. Trois sortes d'appelants, chacun borné :
//   - une session du socle (l'interface de VIGIE) : lecture pour voir, membre
//     pour lancer un audit ou un balayage, admin pour isoler un appareil et
//     pour les réglages — les secrets sous renfort ;
//   - le Hub, par son jeton : lecture, audits et actions (ses workflows) —
//     jamais les réglages ni les secrets ;
//   - un service voisin, par un jeton dérivé que le Hub lui a donné
//     (cer_<nom>_…, vérifié ici sans rien stocker) : lecture et lancement
//     d'un audit, rien d'autre. C'est ce qui sert la page Vigie de MapMyLAN.
import crypto from 'node:crypto';
import { ErreurHttp, Routeur, lireCorps, valider, egal, repondreJson } from '../socle/src/index.js';
import { REF, GRAVITES, RANG, TYPES_ISOLABLES } from './base.js';
import { MODES_IA, FOURNISSEURS } from './ia.js';
import { priorites, REGLES, DOMAINES } from './regles.js';
import { rapportPdf } from './pdf.js';
import { ErreurAction } from './veille.js';
import { PRIVEES, plages, nomAppareil } from './sources.js';
import net from 'node:net';
import { VERSION } from './config.js';
import { MODES, LISTE_BLANCHE_DEFAUT } from './bouclier/riposte.js';
import { observer, empreinteValide, empreinte } from './bouclier/tls.js';
import { plage, normaliser } from './bouclier/ip.js';
import { empreinteJeton } from './bouclier/index.js';
import { litteraleInterdite } from './destination.js';

const T = (max, o = {}) => ({ type: 'chaine', max, ...o });
const B = { type: 'booleen' };
const E = (min, max) => ({ type: 'entier', min, max });
const ID_APPAREIL = /^[A-Za-z0-9_-]{1,64}$/;
const CIDR = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const MODELE = /^[\w.:/-]{1,120}$/;

const S = {
  audit: { ia: B },
  action: { type: T(12, { requis: true, parmi: ['quarantine', 'ban', 'unban', 'deep-scan', 'scan'] }), appareil: T(64, { motif: ID_APPAREIL }), motif: T(200), forcer: B },
  vide: {},
  ia: {
    mode: T(12, { parmi: MODES_IA }), fournisseur: T(12, { parmi: Object.keys(FOURNISSEURS) }), modeleCloud: T(120, { motif: /^([\w.:/-]{1,120})?$/ }),
    modeleLocal: T(120, { motif: /^([\w.:/-]{1,120})?$/ }), cle: T(300, { motif: /^[\x21-\x7e]{20,300}$/ }), retirerCle: B, appelsJour: E(0, 1000), jetonsJour: E(0, 10_000_000),
  },
  essaiIa: { cible: T(8, { requis: true, parmi: ['locale', 'cloud'] }) },
  veille: { actif: B, minutes: E(5, 1440), auditQuotidien: B, heure: E(0, 23), sondeTls: B },
  reaction: { actif: B, types: { type: 'liste', max: 30, de: T(20, { parmi: TYPES_ISOLABLES }) }, parHeure: E(1, 20), seuil: E(50, 100) },
  docker: { jeton: T(300, { motif: /^[\x21-\x7e]{16,300}$/ }), retirerJeton: B },
  perimetre: { exclus: { type: 'liste', max: 100, de: T(18, { motif: CIDR }) } },
  billetterie: { url: T(500, { motif: /^(https?:\/\/\S{3,490})?$/ }), cle: T(300, { motif: /^[\x21-\x7e]{8,300}$/ }), retirerCle: B, entete: T(40, { motif: /^[A-Za-z0-9-]{1,40}$/ }), marqueur: T(32, { motif: /^[a-z0-9_]{1,32}$/i }), seuil: T(10, { parmi: GRAVITES.slice(1) }) },
  telegram: { jeton: T(100, { motif: /^\d{5,15}:[A-Za-z0-9_-]{20,60}$/ }), retirerJeton: B, chat: T(20, { motif: /^(-?\d{1,20})?$/ }), seuil: T(10, { parmi: GRAVITES.slice(1) }) },
  essaiDiffusion: { canal: T(12, { requis: true, parmi: ['billetterie', 'telegram'] }) },
  bouclier: {
    mode: T(12, { parmi: MODES }), seuil: E(30, 1000), seuilInterne: E(30, 1000), demiVieMinutes: E(5, 1440),
    balayagePorts: E(5, 1000), balayageCibles: E(3, 1000), forceBrute: E(3, 1000), autoParHeure: E(1, 2000), maxUnifi: E(10, 10000),
    listesHeures: E(1, 168), listes: { type: 'objet', profondeur: 1 },
    listeBlanche: { type: 'liste', max: 500, de: T(50) }, emetteurs: { type: 'liste', max: 50, de: T(50) },
    listesPropres: { type: 'liste', max: 10, de: { type: 'objet', champs: { nom: T(60, { requis: true }), type: T(8, { requis: true, parmi: ['ip', 'domaine'] }), url: T(500, { requis: true, motif: /^https:\/\/\S{3,490}$/ }), poids: E(5, 100) } } },
    dureesMinutes: { type: 'liste', max: 6, de: E(5, 525600) },
    tempeteSources: E(5, 100000), tempeteLignes: E(50, 1000000), tempeteBlocages: E(0, 500), tempeteMinutes: E(1, 1440), cloudflareModeAttaque: B,
    carnetJours: E(1, 365),
  },
  cloudflare: { jeton: T(200, { motif: /^[A-Za-z0-9_-]{20,200}$/ }), retirer: B, zones: { type: 'liste', max: 50, de: { type: 'objet', champs: { id: T(40, { requis: true, motif: /^[0-9a-f]{32}$/ }), nom: T(253, { requis: true }) } } } },
  cloudflareSonde: { jeton: T(200, { motif: /^[A-Za-z0-9_-]{20,200}$/ }) },
  attaque: { actif: B, minutes: E(1, 1440) },
  bloquer: { ip: T(50, { requis: true }), minutes: E(5, 525600), motif: T(200) },
  unifiSonde: { hote: T(253, { requis: true, motif: /^[A-Za-z0-9.:-]{1,253}$/ }), port: E(1, 65535) },
  unifi: { hote: T(253, { motif: /^[A-Za-z0-9.:-]{1,253}$/ }), port: E(1, 65535), fp: T(80), cle: T(200, { motif: /^[\x21-\x7e]{16,200}$/ }), retirer: B },
  sonde: { nom: T(40, { requis: true, motif: /^[a-z0-9][a-z0-9-]{0,39}$/ }) },
  eve: { evenements: { type: 'liste', max: 5000, de: { type: 'json', profondeur: 6 } } },
  sentinelle: { actif: B, seuil: E(1, 15), seuilEvenement: E(1, 15), correler: B, retentionJours: E(1, 365) },
  essaiSentinelle: { ligne: T(8192, { requis: true }) },
};
const Q = {
  audits: { limite: E(1, 200), statut: T(10, { parmi: ['termine', 'echec', 'en cours'] }) },
  evenements: { limite: E(1, 500), depuis: E(0, 8.64e15), type: T(30, { motif: /^[a-z.]{1,30}$/ }), min: T(10, { parmi: GRAVITES }) },
  constats: { appareil: T(64, { requis: true, motif: ID_APPAREIL }) },
  liste: { jeton: T(80) },
  sentinelle: { limite: E(1, 1000), depuis: E(0, 8.64e15), niveau: E(0, 15), hote: T(253, { motif: /^[A-Za-z0-9._:-]{1,253}$/ }), regle: T(60, { motif: /^[a-z0-9.-]{1,60}$/ }), srcip: T(45, { motif: /^[0-9a-fA-F.:]{1,45}$/ }) },
  flux: { depuis: E(0, 1e12) },
  accueil: { heures: E(1, 720) },
};

/** Le nom d'un jeton dérivé valide (cer_<nom>_<hmac>), ou null. Comparaison à temps constant. */
export function nomDerive(secret, brut) {
  if (!secret || String(secret).length < 16) return null;
  const m = /^cer_([a-z0-9][a-z0-9-]{1,30})_([0-9a-f]{64})$/.exec(String(brut || ''));
  if (!m) return null;
  const attendu = crypto.createHmac('sha256', String(secret)).update('cerveau:' + m[1]).digest();
  const recu = Buffer.from(m[2], 'hex');
  return recu.length === attendu.length && crypto.timingSafeEqual(recu, attendu) ? m[1] : null;
}

/**
 * L'adresse de la billetterie, lue comme une URL (pas comme un préfixe) :
 * https partout, http seulement vers une adresse privée, la machine elle-même
 * ou un conteneur du Hub ; jamais d'identifiants dans l'adresse.
 */
const LOCALES = plages([...PRIVEES, '127.0.0.0/8']);
export function urlBilletterieSure(brute) {
  let u;
  try { u = new URL(brute); } catch { return false; }
  if (u.username || u.password) return false;
  if (litteraleInterdite(brute)) return false;
  if (u.protocol === 'https:') return true;
  if (u.protocol !== 'http:') return false;
  const hote = u.hostname;
  if (hote === 'localhost' || /^hub-[a-z0-9-]{1,60}$/.test(hote)) return true;
  return net.isIPv4(hote) && LOCALES.check(hote, 'ipv4');
}

export function creerApi({ socle, cfg, magasin, moteur, sources, ia, memoire, diffusion, bouclier, sentinelle }) {
  const r = new Routeur();
  const { portail, journal, limiteur } = socle;

  // Qui appelle
  const presente = ctx => { const a = String(ctx.req.headers.authorization || ''); return a.startsWith('Bearer ') ? a.slice(7) : ''; };
  const cleMachine = ctx => [`ip:machine:${ctx.ip}`];
  // Un jeton présenté est vérifié ; un faux compte comme un échec et ne retombe jamais sur la session.
  const appelant = ctx => {
    if (ctx.appelant !== undefined) return ctx.appelant;
    const j = presente(ctx);
    if (!j) return (ctx.appelant = null);
    limiteur.controler(cleMachine(ctx));
    if (egal(j, cfg.jetonHub)) return (ctx.appelant = { type: 'hub', nom: 'hub' });
    const nom = nomDerive(cfg.jetonHub, j);
    if (nom) return (ctx.appelant = { type: 'derive', nom });
    limiteur.echec(cleMachine(ctx));
    journal.rare(`jeton:${ctx.ip}`, { action: 'connexion.jeton', objet: ctx.url.pathname, ip: ctx.ip, resultat: 'refus' });
    throw new ErreurHttp(401, 'Jeton invalide.');
  };
  const session = (ctx, opts = {}) => portail.exiger(ctx, { role: 'lecture', ...opts });
  // Un jeton valable ou une session qui tente au-delà de ce qu'ils ouvrent : refusé, et compté au journal comme les refus du socle.
  const refuser = (ctx, cause, message) => portail.refuser(ctx, cause, message);
  /** qui : 'derive' (lecture et audit), 'hub' (lecture, audits, actions), sinon session seule. */
  const acces = (ctx, { role = 'lecture', jetons = [] } = {}) => {
    const a = appelant(ctx);
    if (a) {
      if (!jetons.includes(a.type)) refuser(ctx, `jeton-${a.type}`, a.type === 'derive' ? 'Ce jeton ne donne que la lecture et le lancement d’un audit.' : 'Réservé à une session de VIGIE.');
      return { type: a.type, nom: a.type === 'derive' ? `service:${a.nom}` : 'hub' };
    }
    const s = session(ctx, { role });
    return { type: 'session', nom: s.compteLigne.identifiant, compte: s.compte, role: s.compteLigne.role };
  };
  const LECTURE = { jetons: ['hub', 'derive'] };
  const corps = async (ctx, schema) => valider(await lireCorps(ctx.req, { limite: 32 * 1024 }), schema);
  const tracer = (ctx, qui, action, objet, details) => journal.ecrire({ acteur: qui.compte ?? null, action, objet, ip: ctx.ip, details: { ...details, par: qui.nom } });
  const actionErreur = e => { if (e instanceof ErreurAction) throw new ErreurHttp(e.status, e.message); throw e; };

  const vueAudit = a => a && { ...a, enCours: moteur.enCours?.id === a.id };
  const etat = () => {
    const dernier = magasin.dernierAudit();
    const ev = magasin.evenements({ limite: 500, depuis: Date.now() - 7 * 86400e3 });
    const iaR = magasin.reglage('ia');
    return {
      version: VERSION, audit: vueAudit(dernier), enCours: moteur.enCours ? vueAudit(magasin.audit(moteur.enCours.id)) : null,
      priorites: dernier ? priorites(magasin.constats(dernier.id)) : [],
      historique: magasin.historique(30), sources: sources.public(), domaines: DOMAINES,
      ia: { mode: iaR.mode, fournisseur: iaR.fournisseur },
      veille: { ...magasin.reglage('veille'), dernierePasse: magasin.memoire('derniere_passe', null) },
      reaction: { actif: magasin.reglage('reaction').actif },
      evenements: { nonAcquittes: ev.filter(e => !e.acquitte && RANG[e.gravite] >= RANG.faible).length, critiques: ev.filter(e => !e.acquitte && e.gravite === 'critique').length },
    };
  };

  r.get('/api/health', () => ({ ok: true }), { public: true });

  // Lecture
  r.get('/api/etat', ctx => { acces(ctx, LECTURE); return etat(); });
  r.get('/api/audits', ctx => {
    acces(ctx, LECTURE);
    const { limite = 50, statut } = ctx.q;
    return magasin.audits(200).filter(a => !statut || a.statut === statut).slice(0, limite).map(vueAudit);
  }, { requete: Q.audits });
  r.get('/api/audits/:id', ctx => {
    acces(ctx, LECTURE);
    const a = magasin.audit(ctx.params.id) || (() => { throw new ErreurHttp(404, 'Audit inconnu.'); })();
    const constats = magasin.constats(a.id);
    return { audit: vueAudit(a), constats, priorites: priorites(constats), regles: REGLES };
  });
  r.get('/api/audits/:id/pdf', ctx => {
    const qui = acces(ctx, LECTURE);
    const a = magasin.audit(ctx.params.id) || (() => { throw new ErreurHttp(404, 'Audit inconnu.'); })();
    if (a.statut !== 'termine') throw new ErreurHttp(409, 'Cet audit n’est pas terminé.');
    const constats = magasin.constats(a.id);
    const historique = magasin.historique(60).filter(h => h.debut <= a.debut);
    const precedent = magasin.audits(200).find(x => x.statut === 'termine' && x.debut < a.debut) || null;
    const pdf = rapportPdf({ audit: { ...a, priorites: priorites(constats) }, constats, historique, precedent });
    tracer(ctx, qui, 'rapport.exporte', a.id, {});
    ctx.res.writeHead(200, {
      'content-type': 'application/pdf', 'content-length': pdf.length, 'cache-control': 'no-store',
      'content-disposition': `attachment; filename="vigie-audit-${new Date(a.debut).toISOString().slice(0, 16).replace(/[:T]/g, '-')}.pdf"`,
    });
    ctx.res.end(pdf);
  });
  r.get('/api/constats', ctx => {
    acces(ctx, LECTURE);
    const { appareil } = ctx.q;
    const a = magasin.dernierAudit();
    if (!a) return { audit: null, constats: [] };
    return { audit: { id: a.id, debut: a.debut, score: a.score }, constats: magasin.constats(a.id).filter(c => c.sujetId === appareil) };
  }, { requete: Q.constats });
  r.get('/api/evenements', ctx => {
    acces(ctx, LECTURE);
    const { limite = 100, depuis = 0, type, min } = ctx.q;
    return magasin.evenements({ limite: 2000, depuis }).filter(e => (!type || e.type === type) && (!min || RANG[e.gravite] >= RANG[min])).slice(0, limite);
  }, { requete: Q.evenements });
  r.get('/api/actions', ctx => { acces(ctx, { jetons: ['hub'] }); return magasin.actions(100); });

  // Audits et veille
  r.post('/api/audits', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub', 'derive'] });
    const b = await corps(ctx, S.audit);
    const out = moteur.lancer({ declencheur: qui.type === 'session' ? 'manuel' : qui.nom, auteur: qui.nom, ia: b.ia !== false });
    if (!out.deja) tracer(ctx, qui, 'audit.lance', out.id, {});
    return out;
  });
  r.post('/api/veille/passe', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub'] });
    await corps(ctx, S.vide);
    tracer(ctx, qui, 'veille.passe', null, {});
    return await moteur.passe();
  });
  r.post('/api/evenements/:id/acquitter', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub'] });
    await corps(ctx, S.vide);
    if (!magasin.acquitter(ctx.params.id, qui.nom)) throw new ErreurHttp(404, 'Événement inconnu ou déjà acquitté.');
    tracer(ctx, qui, 'evenement.acquitte', ctx.params.id, {});
    return { ok: true };
  });

  // Remédiation
  r.post('/api/actions', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub'] });
    const b = await corps(ctx, S.action);
    // Balayer et regarder de près : membre. Couper un appareil du réseau : admin.
    if (!['deep-scan', 'scan'].includes(b.type) && qui.type === 'session' && qui.role !== 'admin') refuser(ctx, 'isolement', 'Droits insuffisants : isoler un appareil est réservé aux administrateurs.');
    if (b.type !== 'scan' && !b.appareil) throw new ErreurHttp(400, 'Champ « appareil » : obligatoire.');
    // Forcer l'isolation d'un équipement d'infrastructure : une session d'administrateur, sous renfort ; jamais un jeton.
    if (b.forcer) {
      if (qui.type !== 'session') refuser(ctx, 'forcer', 'Forcer une isolation est réservé à une session d’administrateur de VIGIE.');
      portail.exiger(ctx, { role: 'admin', renfort: true });
    }
    const x = await moteur.executer({ type: b.type, appareil: b.appareil, motif: b.motif || '', auteur: qui.nom, forcer: !!b.forcer }).catch(actionErreur);
    tracer(ctx, qui, `action.${b.type}`, b.appareil || 'reseau', { etat: x.etat });
    return x;
  });
  r.post('/api/constats/:id/appliquer', async ctx => {
    const qui = acces(ctx, { role: 'admin', jetons: ['hub'] });
    await corps(ctx, S.vide);
    const c = magasin.constat(ctx.params.id) || (() => { throw new ErreurHttp(404, 'Constat inconnu.'); })();
    if (!c.action) throw new ErreurHttp(409, 'Ce constat ne propose pas d’action automatique : sa correction se fait à la main.');
    const x = await moteur.executer({ type: c.action.type, appareil: c.action.appareil, motif: c.titre.slice(0, 200), auteur: qui.nom, constat: c.id }).catch(actionErreur);
    tracer(ctx, qui, `action.${c.action.type}`, c.action.appareil, { constat: c.id, etat: x.etat });
    return x;
  });
  r.post('/api/actions/:id/annuler', async ctx => {
    const qui = acces(ctx, { role: 'admin', jetons: ['hub'] });
    await corps(ctx, S.vide);
    return await moteur.annuler(ctx.params.id, qui.nom).catch(actionErreur);
  });

  // Réglages (session d'administrateur seulement)
  const reglages = () => ({
    ia: ia.etat(), veille: magasin.reglage('veille'), reaction: { ...magasin.reglage('reaction'), typesPossibles: TYPES_ISOLABLES },
    docker: { ...magasin.reglagePublic('docker'), url: cfg.dockerUrl || null }, perimetre: { ...magasin.reglage('perimetre'), plages: sources.perimetreCourant.plages },
    billetterie: { ...magasin.reglagePublic('billetterie'), etat: diffusion.etat.billetterie }, telegram: { ...magasin.reglagePublic('telegram'), etat: diffusion.etat.telegram },
    sources: sources.public(), memoire: memoire.public(),
    // Les sondes : leur nom et leur date, jamais l'empreinte de leur jeton.
    bouclier: { ...magasin.reglagePublic('bouclier'), sondes: (magasin.reglage('bouclier').sondes || []).map(({ nom, cree }) => ({ nom, cree })), listeBlancheDefaut: LISTE_BLANCHE_DEFAUT },
    sentinelle: magasin.reglage('sentinelle'),
  });
  const admin = (ctx, renfort = false) => { if (appelant(ctx)) refuser(ctx, 'jeton-reglages', 'Réservé à une session de VIGIE.'); return portail.exiger(ctx, { role: 'admin', renfort }); };

  r.get('/api/reglages', ctx => { admin(ctx); return reglages(); });

  r.put('/api/reglages/ia', async ctx => {
    const s = admin(ctx);
    const b = await corps(ctx, S.ia);
    // Changer de fournisseur enverrait la clé enregistrée à un autre service : renfort, comme pour la clé.
    const changeFournisseur = b.fournisseur && b.fournisseur !== magasin.reglage('ia').fournisseur && magasin.secret('ia', 'cle');
    if (b.cle || b.retirerCle || changeFournisseur) portail.exiger(ctx, { role: 'admin', renfort: true });
    const { cle, retirerCle, ...reste } = b;
    const futur = { ...magasin.reglage('ia'), ...reste };
    if (['cloud', 'les-deux', 'secours'].includes(futur.mode) && !futur.modeleCloud) throw new ErreurHttp(400, 'Choisis le modèle en nuage avant ce mode.');
    if (['cloud', 'les-deux'].includes(futur.mode) && !cle && (retirerCle || !magasin.secret('ia', 'cle'))) throw new ErreurHttp(400, 'Enregistre une clé d’API avant ce mode.');
    if (['locale', 'les-deux', 'secours'].includes(futur.mode) && !cfg.iaLocaleUrl) throw new ErreurHttp(400, 'Aucune IA locale reliée : installe Ollama depuis le Hub.');
    if (cle) magasin.poserSecret('ia', 'cle', cle);
    if (retirerCle) magasin.poserSecret('ia', 'cle', null);
    magasin.poserReglage('ia', reste);
    journal.ecrire({ acteur: s.compte, action: 'reglages.ia', objet: 'ia', ip: ctx.ip, details: { ...reste, cle: !!cle, retirerCle: !!retirerCle } });
    return reglages();
  });
  r.post('/api/reglages/ia/essai', async ctx => {
    admin(ctx);
    const b = await corps(ctx, S.essaiIa);
    try { return await ia.essai(b.cible); } catch (e) { throw new ErreurHttp(502, `IA ${b.cible === 'locale' ? 'locale' : 'en nuage'} : ${e.message}.`); }
  });
  r.put('/api/reglages/veille', async ctx => {
    // Couper ou espacer la veille aveugle VIGIE : renfort, comme pour le bouclier.
    const s = admin(ctx, true);
    const b = await corps(ctx, S.veille);
    magasin.poserReglage('veille', b);
    journal.ecrire({ acteur: s.compte, action: 'reglages.veille', objet: 'veille', ip: ctx.ip, details: b });
    return reglages();
  });
  r.put('/api/reglages/reaction', async ctx => {
    // Laisser VIGIE agir seul est la décision la plus lourde : renfort exigé.
    const s = admin(ctx, true);
    const b = await corps(ctx, S.reaction);
    magasin.poserReglage('reaction', b);
    journal.ecrire({ acteur: s.compte, action: 'reglages.reaction', objet: 'reaction', ip: ctx.ip, details: b });
    return reglages();
  });
  r.put('/api/reglages/docker', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.docker);
    if (b.jeton) magasin.poserSecret('docker', 'jeton', b.jeton);
    if (b.retirerJeton) magasin.poserSecret('docker', 'jeton', null);
    journal.ecrire({ acteur: s.compte, action: 'reglages.docker', objet: 'docker', ip: ctx.ip, details: { jeton: !!b.jeton, retirerJeton: !!b.retirerJeton } });
    return reglages();
  });
  r.put('/api/reglages/perimetre', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.perimetre);
    for (const x of b.exclus || []) { const [ip, bits] = x.split('/'); if (ip.split('.').some(n => Number(n) > 255) || (bits !== undefined && Number(bits) > 32)) throw new ErreurHttp(400, `Exclusion invalide : ${x}.`); }
    magasin.poserReglage('perimetre', b);
    journal.ecrire({ acteur: s.compte, action: 'reglages.perimetre', objet: 'perimetre', ip: ctx.ip, details: b });
    return reglages();
  });
  r.put('/api/reglages/billetterie', async ctx => {
    const s = admin(ctx);
    const b = await corps(ctx, S.billetterie);
    if (b.cle || b.retirerCle || b.url !== undefined) portail.exiger(ctx, { role: 'admin', renfort: true });
    const { cle, retirerCle, ...reste } = b;
    if (reste.url && !urlBilletterieSure(reste.url)) throw new ErreurHttp(400, 'Billetterie : https:// exigé hors du réseau local, sans identifiants dans l’adresse.');
    if (cle) magasin.poserSecret('billetterie', 'cle', cle);
    if (retirerCle) magasin.poserSecret('billetterie', 'cle', null);
    magasin.poserReglage('billetterie', reste);
    journal.ecrire({ acteur: s.compte, action: 'reglages.billetterie', objet: 'billetterie', ip: ctx.ip, details: { ...reste, cle: !!cle, retirerCle: !!retirerCle } });
    return reglages();
  });
  r.put('/api/reglages/telegram', async ctx => {
    const s = admin(ctx);
    const b = await corps(ctx, S.telegram);
    // Changer de conversation enverrait les alertes ailleurs avec le bot enregistré : renfort, comme pour le jeton.
    const changeChat = b.chat !== undefined && b.chat !== magasin.reglage('telegram').chat && magasin.secret('telegram', 'jeton');
    if (b.jeton || b.retirerJeton || changeChat) portail.exiger(ctx, { role: 'admin', renfort: true });
    const { jeton, retirerJeton, ...reste } = b;
    if (jeton) magasin.poserSecret('telegram', 'jeton', jeton);
    if (retirerJeton) magasin.poserSecret('telegram', 'jeton', null);
    magasin.poserReglage('telegram', reste);
    journal.ecrire({ acteur: s.compte, action: 'reglages.telegram', objet: 'telegram', ip: ctx.ip, details: { ...reste, jeton: !!jeton, retirerJeton: !!retirerJeton } });
    return reglages();
  });
  r.post('/api/reglages/diffusion/essai', async ctx => {
    admin(ctx);
    const b = await corps(ctx, S.essaiDiffusion);
    const e = { id: '', quand: Date.now(), gravite: 'info', type: 'essai', titre: 'Message d’essai de VIGIE', texte: 'Si tu lis ceci, les alertes arrivent.', sujet: '', cle: 'essai' };
    const out = await diffusion[b.canal](e, { forcer: true });
    if (!out.ok) throw new ErreurHttp(502, out.erreur);
    return out;
  });

  // L'accueil : ce qui se passe sur le réseau, ce que VIGIE en a fait, ce qui reste à faire.
  const accueil = async heures => {
    const t = Date.now();
    const depuis = t - heures * 3600e3;
    const db = magasin.db;
    const parType = Object.fromEntries(db.prepare("SELECT type, COUNT(*) n FROM evenements WHERE quand >= ? AND type LIKE 'bouclier.%' GROUP BY type").all(depuis).map(x => [x.type, x.n]));
    const carte = bouclier.carnet.resume({ heures });
    // Les cibles sont des adresses du réseau ou des noms d'hôtes : MapMyLAN donne le nom de celles qu'il connaît.
    if (sources.public().mapmylan?.relie) {
      for (const c of carte.cibles.slice(0, 12)) {
        if (!net.isIP(c.cible)) continue;
        const a = await sources.appareilParIp(c.cible).catch(() => null);
        if (a) c.nom = nomAppareil(a);
      }
    }
    const dernier = magasin.dernierAudit();
    const ev = magasin.evenements({ limite: 500, depuis: t - 7 * 86400e3 });
    const protection = bouclier.protection({ signalees: parType['bouclier.signalee'] || 0 });
    const blocages = bouclier.riposte.blocages({ limite: 6 });
    // À faire : ce qui demande quelqu'un, du plus urgent au moins urgent.
    const aFaire = [];
    if (protection.action && protection.niveau !== 'protege') aFaire.push({ gravite: protection.niveau === 'aveugle' || protection.niveau === 'emetteur' ? 'critique' : 'eleve', titre: protection.titre, texte: protection.texte, action: protection.action });
    const internes = bouclier.correlateur.menacesActuelles({ limite: 3, interne: true }).filter(m => m.score >= m.seuil / 2);
    for (const m of internes) aFaire.push({ gravite: m.score >= m.seuil ? 'critique' : 'eleve', titre: `Machine du réseau suspecte : ${m.ip}`, texte: m.raisons[0]?.texte || `score ${m.score}`, action: { type: 'aller', page: 'bouclier', libelle: 'Examiner' } });
    const critiques = ev.filter(e => !e.acquitte && e.gravite === 'critique').length;
    if (critiques) aFaire.push({ gravite: 'critique', titre: `${critiques} événement${critiques > 1 ? 's' : ''} critique${critiques > 1 ? 's' : ''} à lire`, texte: 'Non acquittés cette semaine.', action: { type: 'aller', page: 'evenements', libelle: 'Lire' } });
    for (const p of (dernier ? priorites(magasin.constats(dernier.id)) : []).slice(0, 3)) aFaire.push({ gravite: p.gravite, titre: p.titre, texte: `${p.sujet ? `${p.sujet} — ` : ''}${p.correction || ''}`.slice(0, 300), action: { type: 'aller', page: 'constats', libelle: 'Voir' } });
    if (bouclier.correlateur.tempete.courante && t - bouclier.correlateur.tempete.courante.quand < 15 * 60e3) {
      const tp = bouclier.correlateur.tempete.courante;
      aFaire.unshift({ gravite: 'critique', titre: `Attaque massive sur le port ${tp.port}`, texte: `${tp.sources.toLocaleString('fr-FR')} sources en une minute.`, action: { type: 'aller', page: 'bouclier', libelle: 'Voir' } });
    }
    return {
      heures, maintenant: t, version: VERSION, protection,
      chiffres: {
        attaques: carte.total, sources: carte.sources, arretees: carte.bloquees, actifs: bouclier.riposte.actifs().length,
        bloquees: parType['bouclier.bloque'] || 0, simulees: parType['bouclier.simule'] || 0, signalees: parType['bouclier.signalee'] || 0,
        alertes: db.prepare('SELECT COUNT(*) n FROM sentinelle_alertes WHERE quand >= ?').get(depuis).n,
      },
      carte, blocages, aFaire: aFaire.slice(0, 6),
      audit: dernier ? { score: dernier.score, debut: dernier.debut, id: dernier.id } : null,
      geo: bouclier.geo.public(),
    };
  };
  r.get('/api/accueil', async ctx => { acces(ctx, LECTURE); return accueil(ctx.q.heures || 24); }, { requete: Q.accueil });

  // Bouclier
  const vueBouclier = () => bouclier.etat();
  r.get('/api/bouclier', ctx => { acces(ctx, LECTURE); return vueBouclier(); });
  r.put('/api/reglages/bouclier', async ctx => {
    // Changer ce que VIGIE bloque seul, ce qu'il ne bloque jamais ou qui il écoute : renfort exigé.
    const s = admin(ctx, true);
    const b = await corps(ctx, S.bouclier);
    for (const x of [...(b.listeBlanche || []), ...(b.emetteurs || [])]) if (!plage(x)) throw new ErreurHttp(400, `Adresse ou plage invalide : ${x}.`);
    if (b.listes) for (const [k, v] of Object.entries(b.listes)) if (!/^[a-z0-9-]{2,40}$/.test(k) || typeof v !== 'boolean') throw new ErreurHttp(400, 'Champ « listes » : identifiant et vrai/faux attendus.');
    for (const l of b.listesPropres || []) if (litteraleInterdite(l.url) || /@/.test(new URL(l.url).host)) throw new ErreurHttp(400, `Liste « ${l.nom} » : adresse refusée (lien local, métadonnées, réservée ou identifiants dans l’adresse).`);
    magasin.poserReglage('bouclier', b);
    bouclier.rafraichir();
    journal.ecrire({ acteur: s.compte, action: 'reglages.bouclier', objet: 'bouclier', ip: ctx.ip, details: { ...b } });
    if (b.listes || b.listesPropres) bouclier.menaces.actualiser().catch(() => null);
    return vueBouclier();
  });
  r.post('/api/bouclier/bloquer', async ctx => {
    const qui = acces(ctx, { role: 'admin', jetons: ['hub'] });
    const b = await corps(ctx, S.bloquer);
    try {
      const x = await bouclier.riposte.bloquer({ ip: b.ip, minutes: b.minutes ?? null, motif: b.motif || 'blocage manuel', raisons: [b.motif || 'blocage manuel'], auteur: qui.nom });
      tracer(ctx, qui, 'bouclier.bloque', x.ip, { minutes: b.minutes ?? null });
      return x;
    } catch (e) { throw new ErreurHttp(e.status || 400, e.message); }
  });
  r.post('/api/bouclier/blocages/:id/lever', async ctx => {
    const qui = acces(ctx, { role: 'admin', jetons: ['hub'] });
    await corps(ctx, S.vide);
    try { return await bouclier.riposte.lever(ctx.params.id, qui.nom); } catch (e) { throw new ErreurHttp(e.status || 400, e.message); }
  });
  r.post('/api/bouclier/listes/actualiser', async ctx => {
    admin(ctx);
    await corps(ctx, S.vide);
    const faits = await bouclier.menaces.actualiser({ forcer: true });
    return { faits, listes: bouclier.menaces.public() };
  });
  // La passerelle : lire son certificat (renfort), puis enregistrer adresse, empreinte et clé.
  r.post('/api/bouclier/unifi/sonde', async ctx => {
    admin(ctx, true);
    const b = await corps(ctx, S.unifiSonde);
    try { return await observer(b.hote, b.port || 443); } catch (e) { throw new ErreurHttp(502, `Passerelle injoignable : ${e.message}.`); }
  });
  r.put('/api/bouclier/unifi', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.unifi);
    if (b.retirer) {
      magasin.poserReglage('bouclier', { unifiHote: '', unifiFp: '' });
      magasin.poserSecret('bouclier', 'cleUnifi', null);
    } else {
      if (!b.hote) throw new ErreurHttp(400, 'Champ « hote » : obligatoire.');
      if (b.fp && !empreinteValide(b.fp)) throw new ErreurHttp(400, 'Empreinte SHA-256 invalide.');
      magasin.poserReglage('bouclier', { unifiHote: b.hote, unifiPort: b.port || 443, unifiFp: b.fp ? empreinte(b.fp) : '' });
      if (b.cle) magasin.poserSecret('bouclier', 'cleUnifi', b.cle);
    }
    journal.ecrire({ acteur: s.compte, action: 'reglages.bouclier.unifi', objet: b.hote || 'unifi', ip: ctx.ip, details: { cle: !!b.cle, fp: !!b.fp, retirer: !!b.retirer } });
    if (!b.retirer) await bouclier.riposte.synchroniser({ forcer: true });
    return vueBouclier();
  });
  r.post('/api/bouclier/unifi/synchroniser', async ctx => {
    admin(ctx);
    await corps(ctx, S.vide);
    return bouclier.riposte.synchroniser({ forcer: true });
  });
  // Cloudflare, en amont
  // Sonder un jeton (celui posé, ou un nouveau avant de l'enregistrer) : compte et zones lisibles.
  r.post('/api/bouclier/cloudflare/sonde', async ctx => {
    admin(ctx);
    const b = await corps(ctx, S.cloudflareSonde);
    const jeton = b.jeton || magasin.secret('bouclier', 'cloudflareJeton');
    if (!jeton) throw new ErreurHttp(400, 'Aucun jeton Cloudflare.');
    try { return await bouclier.riposte.cloudflareFabrique({ jeton }).sonder(); } catch (e) { throw new ErreurHttp(502, e.message); }
  });
  r.put('/api/bouclier/cloudflare', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.cloudflare);
    if (b.retirer) {
      magasin.poserSecret('bouclier', 'cloudflareJeton', null);
      magasin.poserReglage('bouclier', { cloudflareCompte: '', cloudflareZones: [], cloudflareListe: '', cloudflareModeAttaque: false });
      bouclier.riposte.etatCloudflare = { ok: null, erreur: null, synchro: null, envoyees: 0, zones: [], attaque: null };
      magasin.poserMemoire('cloudflare_etat', bouclier.riposte.etatCloudflare);
    } else {
      if (b.jeton) { magasin.poserSecret('bouclier', 'cloudflareJeton', b.jeton); magasin.poserReglage('bouclier', { cloudflareCompte: '', cloudflareListe: '' }); }
      if (b.zones) magasin.poserReglage('bouclier', { cloudflareZones: b.zones.map(z => ({ id: z.id, nom: z.nom.toLowerCase().slice(0, 253) })) });
    }
    journal.ecrire({ acteur: s.compte, action: 'reglages.bouclier.cloudflare', objet: 'cloudflare', ip: ctx.ip, details: { jeton: !!b.jeton, zones: (b.zones || []).length, retirer: !!b.retirer } });
    if (!b.retirer) await bouclier.riposte.synchroniserCloudflare({ forcer: true });
    return bouclier.riposte.etatCloudflare;
  });
  r.post('/api/bouclier/cloudflare/synchroniser', async ctx => { admin(ctx); await corps(ctx, S.vide); return bouclier.riposte.synchroniserCloudflare({ forcer: true }); });
  // Le mode « Under Attack » à la main : on le lève ou on le pose, pour un temps.
  r.post('/api/bouclier/cloudflare/attaque', async ctx => {
    const qui = admin(ctx, true);
    const b = await corps(ctx, S.attaque);
    try { return { attaque: await bouclier.riposte.modeAttaque(!!b.actif, { minutes: b.minutes || 15, auteur: qui.compteLigne.identifiant, motif: 'à la main' }) }; }
    catch (e) { throw new ErreurHttp(e.status || 502, e.message); }
  });
  // Les sondes Suricata : un jeton par sonde, montré une fois, gardé par son empreinte.
  r.post('/api/bouclier/sondes', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.sonde);
    const sondes = (magasin.reglage('bouclier').sondes || []).filter(x => x.nom !== b.nom);
    const jeton = `vgs_${crypto.randomBytes(33).toString('base64url')}`;
    magasin.poserReglage('bouclier', { sondes: [...sondes, { nom: b.nom, empreinte: empreinteJeton(jeton), cree: Date.now() }].slice(-20) });
    journal.ecrire({ acteur: s.compte, action: 'bouclier.sonde.jeton', objet: b.nom, ip: ctx.ip });
    return { nom: b.nom, jeton };
  });
  r.post('/api/bouclier/sondes/retirer', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.sonde);
    magasin.poserReglage('bouclier', { sondes: (magasin.reglage('bouclier').sondes || []).filter(x => x.nom !== b.nom) });
    journal.ecrire({ acteur: s.compte, action: 'bouclier.sonde.retiree', objet: b.nom, ip: ctx.ip });
    return vueBouclier();
  });
  // Ce qu'envoie une sonde : son propre jeton, jamais une session ni le jeton du Hub.
  r.post('/api/sonde/eve', async ctx => {
    const j = presente(ctx);
    limiteur.controler(cleMachine(ctx));
    const nom = bouclier.sondeDuJeton(j);
    if (!nom) {
      limiteur.echec(cleMachine(ctx));
      journal.rare(`sonde:${ctx.ip}`, { action: 'connexion.sonde', objet: '/api/sonde/eve', ip: ctx.ip, resultat: 'refus' });
      throw new ErreurHttp(401, 'Jeton de sonde invalide.');
    }
    const b = valider(await lireCorps(ctx.req, { limite: 4 * 1024 * 1024 }), S.eve);
    return { lues: bouclier.recevoirEve(b.evenements || [], nom) };
  }, { public: true });
  // La liste des adresses bloquées, en texte, pour un pare-feu qui lit une URL :
  // jeton dédié dans l'adresse (ces pare-feu n'envoient pas d'en-tête), ou jeton du Hub.
  r.post('/api/bouclier/jeton-liste', async ctx => {
    const s = admin(ctx, true);
    await corps(ctx, S.vide);
    const jeton = `vgl_${crypto.randomBytes(30).toString('base64url')}`;
    magasin.poserSecret('bouclier', 'jetonListe', jeton);
    journal.ecrire({ acteur: s.compte, action: 'bouclier.liste.jeton', objet: 'liste', ip: ctx.ip });
    return { jeton, chemin: `/api/bouclier/liste.txt?jeton=${jeton}` };
  });
  r.get('/api/bouclier/liste.txt', ctx => {
    const attendu = magasin.secret('bouclier', 'jetonListe');
    const { jeton } = ctx.q;
    if (jeton) {
      limiteur.controler(cleMachine(ctx));
      if (!attendu || !egal(jeton, attendu)) { limiteur.echec(cleMachine(ctx)); throw new ErreurHttp(401, 'Jeton invalide.'); }
    } else acces(ctx, { role: 'lecture', jetons: ['hub'] });
    const t = bouclier.riposte.texteListe();
    ctx.res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(t) });
    ctx.res.end(t);
  }, { public: true, requete: Q.liste });

  // Sentinelle : les journaux d'hôtes
  r.get('/api/sentinelle', ctx => { acces(ctx, LECTURE); return sentinelle.etat(); });
  r.get('/api/sentinelle/alertes', ctx => { acces(ctx, LECTURE); const q = ctx.q; return sentinelle.alertes({ limite: q.limite || 100, depuis: q.depuis || 0, niveau: q.niveau || 0, hote: q.hote || '', regle: q.regle || '', srcip: q.srcip || '' }); }, { requete: Q.sentinelle });
  r.get('/api/sentinelle/regles', ctx => { acces(ctx, LECTURE); return sentinelle.regles(); });
  r.put('/api/reglages/sentinelle', async ctx => {
    // Éteindre la sentinelle ou relever ses seuils la rend sourde : renfort.
    const s = admin(ctx, true);
    const b = await corps(ctx, S.sentinelle);
    magasin.poserReglage('sentinelle', b);
    sentinelle.rafraichir();
    journal.ecrire({ acteur: s.compte, action: 'reglages.sentinelle', objet: 'sentinelle', ip: ctx.ip, details: b });
    return magasin.reglage('sentinelle');
  });
  // Comme un banc d'essai de règles : ce que la sentinelle ferait d'une ligne, sans rien retenir.
  r.post('/api/sentinelle/essai', async ctx => { admin(ctx); const b = await corps(ctx, S.essaiSentinelle); return sentinelle.essai(b.ligne); });
  // Le direct : observations du bouclier et événements de la sentinelle, en flux (SSE), pour une session.
  r.get('/api/sentinelle/flux', ctx => {
    session(ctx);
    const depuis = Number(ctx.q.depuis || ctx.req.headers['last-event-id'] || 0) || 0;
    try { sentinelle.abonner(ctx.res, depuis); } catch (e) { throw new ErreurHttp(e.status || 500, e.message); }
  }, { requete: Q.flux });

  return {
    async traiter(ctx) {
      const p = ctx.url.pathname;
      if (!p.startsWith('/api/')) return false;
      const t = r.trouver(ctx.req.method, p);
      if (!t) throw new ErreurHttp(404, 'Route inconnue.');
      if (t.methodes) { ctx.res.setHeader('Allow', t.methodes.join(', ')); throw new ErreurHttp(405, 'Méthode non admise.'); }
      if (Object.values(t.params).some(v => !REF.test(v))) throw new ErreurHttp(404, 'Introuvable.');
      ctx.params = t.params;
      const schema = t.route.options?.requete;
      if (!schema && ctx.url.search) throw new ErreurHttp(400, 'Paramètres de requête inattendus.');
      Object.defineProperty(ctx, 'q', { configurable: true, get: () => valider(Object.fromEntries(ctx.url.searchParams), schema || {}) });
      const reponse = await t.route.gestionnaire(ctx);
      // Une route qui n'a pas lu ses paramètres (une branche qui rend tôt) les fait valider ici, avant de répondre.
      if (schema && ctx.url.search && !ctx.res.headersSent) void ctx.q;
      if (reponse !== undefined) repondreJson(ctx.res, 200, reponse);
      return true;
    },
    routeur: r,
  };
}
