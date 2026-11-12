// Interface de VIGIE : tableau de bord, constats (par constat ou par hôte),
// historique des audits, événements de la veille, actions, réglages, et les
// pages Sécurité et Comptes du socle. La porte du socle gère la connexion ;
// le serveur revérifie chaque droit.
//
// Rien n'est injecté comme balisage : tout passe par h(), qui écrit du texte.
import {
  Api, porte, pageSecurite, pageComptes, h, icone, basculeTheme, appliquerTheme,
  toast, confirmer, dialogue, feuille, ajouterPictos,
} from '/socle/compte.js';
import { pageBouclier } from './bouclier.js';
import { pageSentinelle } from './sentinelle.js';
import { pageAccueil, pageAttaques } from './accueil.js';

// Les logos de VIGIE, dans la couleur du texte (mêmes tracés que le dossier
// Logo) : la marque seule pour les tuiles et l'écran de connexion, le logo
// complet avec le nom pour la barre.
const LOGO_NS = 'http://www.w3.org/2000/svg';
function dessinLogo(vb, traces, largeur, hauteur, nom) {
  const s = document.createElementNS(LOGO_NS, 'svg');
  s.setAttribute('width', largeur); s.setAttribute('height', hauteur); s.setAttribute('viewBox', vb);
  if (nom) { s.setAttribute('role', 'img'); s.setAttribute('aria-label', nom); } else s.setAttribute('aria-hidden', 'true');
  for (const [d, regle] of traces) {
    const p = document.createElementNS(LOGO_NS, 'path');
    p.setAttribute('d', d); p.setAttribute('fill', 'currentColor');
    if (regle) p.setAttribute('fill-rule', regle);
    s.append(p);
  }
  return s;
}
const LOGO_MARQUE = ['6.4 4 244 244', [['M118,228L235.8,24L151.6,72.7L90,179.5ZM21,60L114,113.7L83,167.4Z']]];
const LOGO_TEXTE = ['9 12 704.14 228', [['M118,228L235.8,24L151.6,72.7L90,179.5ZM21,60L114,113.7L83,167.4ZM360.74,80L380.98,80L388.84,144.4L428.82,80L449.06,80L391.16,172L372.76,172ZM458.26,80L476.66,80L453.72,172L435.32,172ZM564.12,172L472.12,172L495.06,80L587.06,80L582.47,98.4L508.87,98.4L495.11,153.6L550.31,153.6L554.9,135.2L527.3,135.2L531.42,118.64L577.42,118.64ZM601.78,80L620.18,80L597.24,172L578.84,172ZM634.9,80L701.14,80L696.55,98.4L648.71,98.4L644.12,116.8L684.6,116.8L680.02,135.2L639.54,135.2L634.95,153.6L682.79,153.6L678.2,172L611.96,172Z']]];
function logoMarque(taille = 16) {
  const s = dessinLogo(LOGO_MARQUE[0], LOGO_MARQUE[1], taille, taille, '');
  s.setAttribute('class', 'logo-marque');
  return s;
}
function logoTexte(hauteur = 20) {
  const s = dessinLogo(LOGO_TEXTE[0], LOGO_TEXTE[1], Math.round(hauteur * 3.0883), hauteur, 'VIGIE');
  s.setAttribute('class', 'logo-texte');
  return s;
}

appliquerTheme();
const SERVICE = 'VIGIE';
const api = new Api({ surDeconnexion: () => location.reload() });
const etatPorte = await porte({ api, service: SERVICE, marque: logoMarque(20), sousTitre: 'audit et veille du réseau' });
const moi = etatPorte.session.compte;
const admin = moi.role === 'admin';
const membre = admin || moi.role === 'membre';

ajouterPictos({
  oeil: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  liste: '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1"/><circle cx="4.5" cy="12" r="1"/><circle cx="4.5" cy="18" r="1"/>',
  serveur: '<rect x="4" y="4" width="16" height="7" rx="2"/><rect x="4" y="13" width="16" height="7" rx="2"/><path d="M8 7.5h.01M8 16.5h.01"/>',
  cloche: '<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
  eclair: '<path d="M13 3 5 13.5h6L10 21l8-10.5h-6z"/>',
  reglages: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2.2"/><circle cx="7.5" cy="17" r="2.2"/>',
  telecharger: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  jouer: '<path d="M7 5v14l11-7z"/>',
  actions: '<circle cx="5" cy="12" r="1.4"/><circle cx="12" cy="12" r="1.4"/><circle cx="19" cy="12" r="1.4"/>',
  courbe: '<path d="M3 17l5-5 4 3 8-8"/><path d="M15 7h5v5"/>',
  muraille: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18M3 15h18M9 5v5M15 10v5M9 15v4"/>',
  puce: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  maison: '<path d="M4 11.2 12 4.5l8 6.7"/><path d="M6.2 9.6V19.5h11.6V9.6"/><path d="M10 19.5v-5h4v5"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.4 3.6 5.2 3.6 8.5s-1.2 6.1-3.6 8.5c-2.4-2.4-3.6-5.2-3.6-8.5S9.6 5.9 12 3.5z"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6.5-6.5M12 3v2M21 12h-2"/>',
});

const GRAVITES = ['critique', 'eleve', 'faible', 'info', 'safe'];
const LIB = { safe: 'Conforme', info: 'Info', faible: 'Faible', eleve: 'Élevé', critique: 'Critique' };
const ICONE_G = { safe: 'verifie', info: 'oeil', faible: 'alerte', eleve: 'alerte', critique: 'eclair' };
const ACTION_LIB = { quarantine: 'Mise en quarantaine', ban: 'Bannissement', unban: 'Retour au réseau', 'deep-scan': 'Balayage approfondi', scan: 'Balayage du réseau' };
const ETAT_ACTION = { appliquee: 'appliquée', restauree: 'n’a pas pris', echec: 'échec', annulee: 'annulée', averifier: 'à vérifier' };
const SOURCES = { mapmylan: 'MapMyLAN', nexarc: 'NEXARC', docker: 'docker-control', tls: 'Sondes TLS', synapse: 'SYNAPSE' };
const MODES_IA = { aucune: 'Aucune — le moteur de règles seul', locale: 'Locale — rien ne sort du réseau', cloud: 'En nuage — meilleure rédaction', 'les-deux': 'Les deux — la locale relit, le nuage tranche', secours: 'Secours — locale, nuage si elle échoue' };
const sur = fn => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };
const quand = t => new Date(t).toLocaleString('fr-FR', { dateStyle: 'medium', timeStyle: 'short' });
const classeScore = s => (s === null || s === undefined ? '' : s >= 80 ? 's-bon' : s >= 60 ? 's-moyen' : s >= 40 ? 's-faible' : 's-mauvais');
const chipG = g => h('span', { class: `chip g-${g}`, text: LIB[g] });
const pluriel = (n, mot, pl = mot + 's') => `${n} ${n > 1 ? pl : mot}`;

let domaines = {};
const stage = h('div', { class: 'stage' });
const navs = {};
const contexte = () => ({ api, admin, sur, aller, suivre, majRail });
const PAGES = {
  accueil: { titre: 'Accueil', ic: 'maison', rendre: () => pageAccueil(contexte()) },
  attaques: { titre: 'Attaques', ic: 'globe', rendre: p => pageAttaques(contexte(), p) },
  tableau: { titre: 'Posture', ic: 'bouclier', rendre: pageTableau },
  constats: { titre: 'Constats', ic: 'liste', rendre: pageConstats },
  historique: { titre: 'Historique', ic: 'courbe', rendre: pageHistorique },
  // recharger : la même page, dans la même vue (le hash porte l'onglet).
  bouclier: { titre: 'Bouclier', ic: 'muraille', rendre: p => pageBouclier({ api, admin, sur, quand, interrupteur, suivre, aller, params: p, recharger: () => aller(location.hash.slice(1) || 'bouclier') }) },
  sentinelle: { titre: 'Sentinelle', ic: 'radar', rendre: p => pageSentinelle({ api, admin, sur, quand, interrupteur, suivre, aller, params: p, recharger: () => aller(location.hash.slice(1) || 'sentinelle') }) },
  evenements: { titre: 'Événements', ic: 'cloche', rendre: pageEvenements },
  actions: { titre: 'Actions', ic: 'eclair', rendre: pageActions },
  ...(admin ? { reglages: { titre: 'Réglages', ic: 'reglages', rendre: pageReglages } } : {}),
  securite: { titre: 'Sécurité', ic: 'cadenas', rendre: () => pageSecurite(api, { service: SERVICE, confidentialite: '/confidentialite.txt' }) },
  ...(admin ? { comptes: { titre: 'Comptes', ic: 'utilisateurs', rendre: () => pageComptes(api, { service: SERVICE }) } } : {}),
};
const lien = k => (navs[k] = h('button', { class: 'nav', type: 'button', 'aria-label': PAGES[k].titre, onclick: () => aller(k) }, icone(PAGES[k].ic), h('span', { text: PAGES[k].titre })));
const groupe = (nom, cles) => { const l = cles.filter(k => PAGES[k]); return l.length ? h('div', { class: 'grp' }, h('span', { text: nom }), l.map(lien)) : null; };
const railScore = h('b', { text: '—' });
const railBar = h('i');
const app = h('div', { class: 'app' },
  h('nav', { class: 'rail', 'aria-label': 'Navigation' },
    h('div', { class: 'mark' }, logoTexte(24), h('i', { class: 'pulse' })),
    groupe('Réseau', ['accueil', 'attaques', 'bouclier', 'sentinelle']),
    groupe('Audit', ['tableau', 'constats', 'historique']),
    groupe('Veille', ['evenements', 'actions']),
    groupe('Système', ['reglages', 'securite', 'comptes']),
    h('div', { class: 'railcard' },
      h('div', { class: 'row' }, icone('bouclier', 14), h('span', { class: 'tronque', text: 'Score' }), railScore),
      h('div', { class: 'bar' }, railBar),
      h('div', { class: 'row mt12' }, icone('utilisateurs', 14), h('span', { class: 'tronque', text: moi.identifiant })),
      h('button', { class: 'btn sm flat plein', type: 'button', onclick: async () => { await api.post('/api/compte/deconnexion'); location.reload(); } }, icone('sortie', 14), 'Se déconnecter'))),
  h('div', { class: 'voile-rail', onclick: () => app.classList.remove('menu-ouvert') }),
  h('main', { class: 'main' },
    h('header', { class: 'top' },
      h('button', { class: 'ghost menu', type: 'button', 'aria-label': 'Menu', onclick: () => app.classList.toggle('menu-ouvert') }, icone('menu')),
      h('div', { class: 'topright' }, basculeTheme(), h('div', { class: 'who', title: moi.identifiant, text: moi.identifiant.slice(0, 2).toUpperCase() }))),
    stage));
document.body.append(app);

let minuteur = null;
let generation = 0;
// Une page qui se repeint seule : la boucle s'arrête dès qu'on en change.
function suivre(peindre, ms) {
  const g = generation;
  const tour = () => { minuteur = setTimeout(async () => { if (g !== generation) return; try { await peindre(); } catch { /* déconnecté : la porte s'en charge */ } if (g === generation) tour(); }, ms); };
  tour();
}
async function aller(cible) {
  const [k0, requete = ''] = cible.split('?');
  const k = PAGES[k0] ? k0 : 'accueil';
  clearTimeout(minuteur);
  generation++;
  for (const [n, b] of Object.entries(navs)) b.classList.toggle('on', n === k);
  app.classList.remove('menu-ouvert');
  history.replaceState(null, '', '#' + k + (requete ? '?' + requete : ''));
  try { stage.replaceChildren(await PAGES[k].rendre(new URLSearchParams(requete))); } catch (e) { stage.replaceChildren(h('div', { class: 'page' }, h('p', { class: 'erreur', text: e.message }))); }
  stage.scrollTop = 0;
}
function majRail(e) {
  const s = e.audit?.score;
  railScore.textContent = s === null || s === undefined ? '—' : `${s} / 100`;
  railBar.style.width = (s ?? 0) + '%';
  railBar.className = classeScore(s);
}

const interrupteur = (marche, libelle, surChange) => {
  const b = h('button', { class: 'toggle', type: 'button', role: 'switch', 'aria-checked': String(!!marche), 'aria-label': libelle }, h('i'));
  b.addEventListener('click', () => { const v = b.getAttribute('aria-checked') !== 'true'; b.setAttribute('aria-checked', String(v)); surChange?.(v); });
  b.valeur = () => b.getAttribute('aria-checked') === 'true';
  return b;
};
const ligneReglage = (titre, aide, controle) => h('div', { class: 'reglage-ligne' }, h('div', {}, h('strong', { text: titre }), aide ? h('small', { text: aide }) : null), controle);
const telecharger = async (chemin, nom) => {
  const r = await fetch(chemin, { credentials: 'same-origin' });
  if (!r.ok) { let m = 'Téléchargement impossible.'; try { m = (await r.json()).error || m; } catch { /* corps non JSON */ } throw new Error(m); }
  const a = h('a', { href: URL.createObjectURL(await r.blob()), download: nom });
  document.body.append(a); a.click(); a.remove();
};
const pdf = a => telecharger(`/api/audits/${a.id}/pdf`, `vigie-audit-${new Date(a.debut).toISOString().slice(0, 10)}.pdf`);
const lancerAudit = sur(async () => {
  const o = await api.post('/api/audits', {});
  toast(o.deja ? 'Un audit est déjà en cours.' : 'Audit lancé.');
  await aller('tableau');
});

// Dessins
const SVG = 'http://www.w3.org/2000/svg';
const s = (tag, attrs = {}) => { const e = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };

function anneau(score, delta) {
  const r = 52, c = 2 * Math.PI * r, part = 0.75;
  const svg = s('svg', { viewBox: '0 0 120 120', 'aria-hidden': 'true' });
  const fond = s('circle', { cx: 60, cy: 60, r, fill: 'none', 'stroke-width': 10, class: 'fond', 'stroke-linecap': 'round', 'stroke-dasharray': `${c * part} ${c}`, transform: 'rotate(135 60 60)' });
  const arc = s('circle', { cx: 60, cy: 60, r, fill: 'none', 'stroke-width': 10, class: `val ${classeScore(score)}`, 'stroke-linecap': 'round', 'stroke-dasharray': `${c * part * (score ?? 0) / 100} ${c}`, transform: 'rotate(135 60 60)' });
  svg.append(fond, ...(score ? [arc] : []));
  return h('div', {},
    h('div', { class: 'anneau', role: 'img', 'aria-label': `Score ${score ?? 'non évalué'} sur 100` }, svg, h('div', { class: 'chiffre' }, h('b', { text: score ?? '—' }), h('span', { text: 'score / 100' }))),
    delta === null || delta === undefined ? null : h('p', { class: `tendance ${delta > 0 ? 'hausse' : delta < 0 ? 'baisse' : ''}`, text: delta === 0 ? 'stable depuis le dernier audit' : `${delta > 0 ? '+' : ''}${delta} depuis le dernier audit` }));
}

function barresDomaines(a) {
  return h('div', { class: 'domaines' }, Object.entries(domaines).map(([k, nom]) => {
    const d = a.domaines?.[k];
    const ne = d?.score === null || d?.score === undefined;
    const bar = h('i', { class: classeScore(d?.score) });
    bar.style.width = (ne ? 0 : d.score) + '%';
    return h('div', { class: 'domaine' }, h('span', { text: nom }), h('b', { class: ne ? 'ne' : '', text: ne ? 'non évalué' : String(d.score) }), h('div', { class: 'bar' }, bar));
  }));
}

function distribution(dist) {
  const total = GRAVITES.reduce((x, g) => x + (dist?.[g] || 0), 0) || 1;
  const barre = h('div', { class: 'distribution', role: 'img', 'aria-label': GRAVITES.map(g => `${dist?.[g] || 0} ${LIB[g]}`).join(', ') },
    [...GRAVITES].reverse().map(g => { const i = h('i', { class: `g-${g}` }); i.style.width = (100 * (dist?.[g] || 0) / total) + '%'; return i; }));
  const legende = h('div', { class: 'legende' }, GRAVITES.map(g => h('span', {}, h('i', { class: `pastille g-${g}` }), h('b', { text: dist?.[g] || 0 }), LIB[g])));
  return [barre, legende];
}

function courbe(historique) {
  const pts = historique.filter(p => p.score !== null && p.score !== undefined);
  if (pts.length < 2) return h('p', { class: 'vide', text: 'La courbe apparaît à partir du deuxième audit.' });
  const L = 600, H = 100, t0 = pts[0].debut, t1 = pts.at(-1).debut;
  const x = t => 8 + (L - 16) * (t1 === t0 ? 1 : (t - t0) / (t1 - t0));
  const y = v => 6 + (H - 12) * (1 - v / 100);
  const svg = s('svg', { viewBox: `0 0 ${L} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': `Score de ${pts[0].score} à ${pts.at(-1).score}` });
  for (const v of [0, 50, 100]) svg.append(s('line', { x1: 0, x2: L, y1: y(v), y2: y(v), class: 'grille-l', 'stroke-width': 1, 'vector-effect': 'non-scaling-stroke' }));
  const d = pts.map((p, i) => `${i ? 'L' : 'M'}${x(p.debut).toFixed(1)} ${y(p.score).toFixed(1)}`).join(' ');
  svg.append(s('path', { d: `${d} L${x(t1).toFixed(1)} ${H} L${x(t0).toFixed(1)} ${H} Z`, class: 'aire', opacity: 0.6 }), s('path', { d, class: 'ligne', 'vector-effect': 'non-scaling-stroke' }));
  return h('div', { class: 'courbe' }, svg, h('div', { class: 'bornes' }, h('span', { text: new Date(t0).toLocaleDateString('fr-FR') }), h('span', { text: new Date(t1).toLocaleDateString('fr-FR') })));
}

function carteSources(sources) {
  return h('div', { class: 'card carte-pleine' }, h('header', {}, h('h2', { text: 'Sources' }), h('span', { class: 'note', text: 'ce que VIGIE lit' })),
    h('div', { class: 'corps-plein' }, Object.entries(SOURCES).map(([k, nom]) => {
      const x = sources[k] || {};
      const t = !x.relie ? h('span', { class: 'tag idle' }, h('i', { class: 'd' }), 'non reliée')
        : x.ok === false ? h('span', { class: 'tag held' }, h('i', { class: 'd' }), 'en échec')
          : x.ok ? h('span', { class: 'tag' }, h('i', { class: 'd' }), 'lue') : h('span', { class: 'tag idle' }, h('i', { class: 'd' }), 'reliée');
      const aide = !x.relie ? { mapmylan: 'Installe MapMyLAN depuis le Hub : il est la source principale.', nexarc: 'Facultatif : postes, antivirus, correctifs.', docker: 'Facultatif : jeton à poser dans les réglages.', tls: 'Coupées dans les réglages de la veille.', synapse: 'Facultatif : mémoire des audits.' }[k]
        : x.erreur || (x.quand ? `lue le ${quand(x.quand)}${x.n !== undefined ? ` · ${pluriel(x.n, 'élément')}` : ''}` : '');
      return h('div', { class: 'etat-source' }, h('span', { class: 'itile' }, icone(k === 'tls' ? 'cadenas' : k === 'docker' ? 'puce' : 'serveur', 15)), h('div', {}, h('strong', { text: nom }), aide ? h('small', { text: aide }) : null), t);
    })));
}

// Tableau de bord
async function pageTableau() {
  const e = await api.get('/api/etat');
  domaines = e.domaines;
  majRail(e);
  if (e.enCours) minuteur = setTimeout(() => { if (location.hash.startsWith('#tableau')) aller('tableau'); }, 2500);
  const a = e.audit;
  const iaEnCours = a?.ia?.statut === 'en cours';
  if (iaEnCours && !e.enCours) minuteur = setTimeout(() => aller('tableau'), 3000);
  const entete = h('div', { class: 'headrow' },
    h('div', {}, h('h1', { class: 'title', text: 'Posture de sécurité' }),
      h('p', { class: 'lede', text: a ? `Audit du ${quand(a.debut)} · ${a.declencheur}${e.ia.mode !== 'aucune' ? ` · IA ${e.ia.mode}` : ' · sans IA'}${e.veille.actif ? ` · veille toutes les ${e.veille.minutes} min` : ' · veille coupée'}` : 'Aucun audit encore. Le premier lit les sources reliées, applique les règles et donne un score.' })),
    h('div', { class: 'actions' },
      a ? h('button', { class: 'btn', type: 'button', onclick: sur(() => pdf(a)) }, icone('telecharger', 15), 'Exporter le PDF') : null,
      membre ? h('button', { class: 'btn solid', type: 'button', disabled: !!e.enCours, onclick: lancerAudit }, icone('jouer', 15), e.enCours ? 'Audit en cours…' : 'Lancer un audit') : null));
  if (!a) {
    return h('div', { class: 'page' }, entete,
      e.enCours ? h('div', { class: 'card' }, h('p', { class: 'vide', text: 'Premier audit en cours : collecte, règles, score…' })) : null,
      carteSources(e.sources));
  }
  const histo = e.historique;
  const prec = histo.length >= 2 ? histo.at(-2).score : null;
  const delta = prec !== null && a.score !== null ? a.score - prec : null;
  // Les priorités sont celles du moteur (règles et gravités) ; l'IA propose des pistes à côté, jamais à leur place.
  const prio = e.priorites.map(p => ({ titre: p.titre, texte: `${p.sujet ? p.sujet + ' — ' : ''}${p.correction}`, gravite: p.gravite }));
  const pistes = (a.ia?.priorites || []).map(p => ({ titre: p.titre, texte: p.pourquoi }));
  return h('div', { class: 'page' }, entete,
    e.evenements.critiques ? h('div', { class: 'card' }, h('div', { class: 'notice' }, h('span', { class: 'itile g-critique' }, icone('eclair', 15)),
      h('div', {}, h('p', { text: `${pluriel(e.evenements.critiques, 'événement critique', 'événements critiques')} non acquitté${e.evenements.critiques > 1 ? 's' : ''} cette semaine.` })),
      h('button', { class: 'btn sm', type: 'button', onclick: () => aller('evenements') }, 'Voir'))) : null,
    // Deux colonnes qui s'empilent chacune à sa hauteur : pas de vide sous le score.
    h('div', { class: 'colonnes' },
      h('div', { class: 'colonne' },
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Score' }), h('span', { class: 'note', text: a.score === null ? 'non évalué' : 'recalculé à chaque audit' })),
        h('div', { class: 'score-carte' }, anneau(a.score, delta), barresDomaines(a))),
        h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Évolution du score' })), courbe(histo)),
        carteIA(a.ia, e.ia)),
      h('div', { class: 'colonne' },
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Constats' }), h('button', { class: 'btn sm flat', type: 'button', onclick: () => aller('constats') }, 'Tout voir')),
        ...distribution(a.distribution),
        h('header', {}, h('h2', { text: 'Priorités du moment' })),
        prio.length ? prio.map((p, i) => h('div', { class: 'priorite' }, h('span', { class: 'rang', text: i + 1 }), h('div', {}, h('strong', { text: p.titre }), p.texte ? h('small', { text: p.texte }) : null)))
          : h('p', { class: 'vide', text: 'Rien à corriger en priorité.' }),
        pistes.length ? h('header', {}, h('h2', { text: 'Pistes de l’IA' }), h('span', { class: 'note', text: 'à vérifier' })) : null,
        ...pistes.map(p => h('div', { class: 'priorite' }, h('span', { class: 'rang', text: '·' }), h('div', {}, h('strong', { text: p.titre }), p.texte ? h('small', { text: p.texte }) : null)))),
        carteSources(e.sources))));
}

function carteIA(ia = {}, reglage) {
  const entete = t => h('header', {}, h('h2', { text: 'Relecture de l’IA' }), h('span', { class: 'note', text: t }));
  if (ia.statut === 'faite') {
    return h('div', { class: 'card carte-pleine' }, entete(`${ia.moteur === 'locale' ? 'locale' : ia.moteur === 'cloud' ? 'en nuage' : 'locale puis nuage'} · ${ia.modele || ''}`),
      h('div', { class: 'corps-plein' },
        ia.synthese ? h('p', { class: 'synthese', text: ia.synthese }) : null,
        (ia.scenarios || []).map(x => h('div', { class: 'scenario' }, h('strong', { text: x.titre }), h('p', { text: x.explication }))),
        ia.erreurs?.length ? h('p', { class: 'hint pad-erreur', text: `Incidents : ${ia.erreurs.join(' ; ')}` }) : null),
      h('p', { class: 'hint pad-erreur', text: 'L’IA confirme, nuance ou écarte les constats ; elle ne change ni les gravités ni le score.' }));
  }
  const texte = ia.statut === 'en cours' ? 'L’IA relit l’audit…'
    : ia.statut === 'ignoree' ? `Pas de relecture : ${ia.raison}${ia.erreurs?.length ? ` (${ia.erreurs.join(' ; ')})` : ''}.`
      : reglage.mode === 'aucune' ? 'Aucune IA choisie : l’audit vient du seul moteur de règles, complet sans elle.' + (admin ? ' Réglages → IA pour en brancher une, locale ou en nuage.' : '')
        : 'Cet audit n’a pas été relu.';
  return h('div', { class: 'card carte-pleine' }, entete(ia.statut === 'en cours' ? 'en cours' : reglage.mode), h('div', { class: 'corps-plein' }, h('p', { class: 'synthese', text: texte })));
}

// Constats
async function pageConstats(q) {
  const e = await api.get('/api/etat');
  domaines = e.domaines;
  majRail(e);
  const id = q.get('audit') || e.audit?.id;
  if (!id) return h('div', { class: 'page' }, h('div', { class: 'headrow' }, h('h1', { class: 'title', text: 'Constats' })), h('div', { class: 'card' }, h('p', { class: 'vide', text: 'Aucun audit encore.' })));
  const { audit, constats } = await api.get(`/api/audits/${id}`);
  let filtreG = q.get('gravite') || 'ecarts', filtreD = '', vue = q.get('vue') || 'constats';
  const liste = h('div', {});
  const compte = g => (g === 'ecarts' ? constats.filter(c => c.gravite !== 'safe').length : g === 'tous' ? constats.length : constats.filter(c => c.gravite === g).length);
  const choix = [['ecarts', 'Écarts'], ['tous', 'Tous'], ...GRAVITES.map(g => [g, LIB[g]])];
  const boutonsG = choix.map(([g, t]) => h('button', { class: `chip filtre ${g !== 'ecarts' && g !== 'tous' ? 'g-' + g : ''}`, type: 'button', 'aria-pressed': 'false', onclick: () => { filtreG = g; peindre(); } }, `${t} · ${compte(g)}`));
  const selD = h('select', { class: 'field', 'aria-label': 'Domaine', onchange: () => { filtreD = selD.value; peindre(); } }, h('option', { value: '', text: 'Tous les domaines' }), Object.entries(domaines).map(([k, n]) => h('option', { value: k, text: n })));
  const vues = h('div', { class: 'views' }, [['constats', 'Par constat'], ['hotes', 'Par hôte']].map(([v, t]) => h('button', { class: 'view', type: 'button', dataset: { v }, onclick: () => { vue = v; peindre(); } }, t)));
  const choisis = () => constats.filter(c => (filtreG === 'tous' || (filtreG === 'ecarts' ? c.gravite !== 'safe' : c.gravite === filtreG)) && (!filtreD || c.domaine === filtreD));
  function peindre() {
    boutonsG.forEach((b, i) => { b.classList.toggle('on', choix[i][0] === filtreG); b.setAttribute('aria-pressed', String(choix[i][0] === filtreG)); });
    for (const b of vues.children) b.classList.toggle('on', b.dataset.v === vue);
    const l = choisis();
    if (!l.length) { liste.replaceChildren(h('p', { class: 'vide', text: 'Aucun constat pour ce filtre.' })); return; }
    if (vue === 'constats') { liste.replaceChildren(...l.map(ligneConstat)); return; }
    const parHote = new Map();
    for (const c of l) { const k = c.sujet || 'Réseau entier'; parHote.set(k, [...(parHote.get(k) || []), c]); }
    const rang = c => GRAVITES.indexOf(c.gravite);
    liste.replaceChildren(...[...parHote.entries()].sort((x, y) => Math.min(...x[1].map(rang)) - Math.min(...y[1].map(rang)) || x[0].localeCompare(y[0])).map(([nom, cs]) => {
      const pire = cs.reduce((x, c) => (rang(c) < rang(x) ? c : x), cs[0]).gravite;
      const ecarts = cs.filter(c => c.gravite !== 'safe').length;
      return h('details', { class: 'hote' }, h('summary', {}, h('span', { class: `itile g-${pire}` }, icone(ICONE_G[pire], 15)),
        h('div', { class: 'grow1' }, h('strong', { text: nom }), h('small', { text: `${pluriel(cs.length, 'constat')} · ${ecarts ? pluriel(ecarts, 'écart') : 'aucun écart'}` })), chipG(pire)), cs.map(ligneConstat));
    }));
  }
  const ligneConstat = c => h('div', { class: `flowrow cliquable ${c.ia?.statut === 'ecarte' ? 'ecarte' : ''}`, role: 'button', tabindex: '0', 'data-donnee': '', onclick: () => ficheConstat(c), onkeydown: ev => { if (ev.key === 'Enter') ficheConstat(c); } },
    h('span', { class: `itile g-${c.gravite}` }, icone(ICONE_G[c.gravite], 15)),
    h('div', { class: 'grow1' }, h('strong', { text: c.titre }), h('small', { text: [c.sujet, domaines[c.domaine], c.ref].filter(Boolean).join(' · ') })),
    h('div', { class: 'fin' }, c.ia ? h('span', { class: 'chip', title: c.ia.note, text: c.ia.statut === 'confirme' ? 'IA : confirmé' : c.ia.statut === 'nuance' ? 'IA : nuancé' : 'IA : écarté' }) : null, chipG(c.gravite)));
  peindre();
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' },
      h('div', {}, h('h1', { class: 'title', text: 'Constats' }), h('p', { class: 'lede', text: `Audit du ${quand(audit.debut)} · score ${audit.score ?? '—'} · ${pluriel(constats.length, 'contrôle')} évalué${constats.length > 1 ? 's' : ''}. Chaque constat est rattaché à un contrôle du référentiel Codex64.` })),
      h('div', { class: 'actions' }, vues, audit.statut === 'termine' ? h('button', { class: 'btn', type: 'button', onclick: sur(() => pdf(audit)) }, icone('telecharger', 15), 'PDF') : null)),
    h('div', { class: 'filtres' }, boutonsG, selD),
    h('div', { class: 'card' }, liste));

  async function ficheConstat(c) {
    const preuve = Object.entries(c.preuve || {}).filter(([, v]) => v !== null && v !== '' && !(Array.isArray(v) && !v.length));
    const valeur = (v, k) => (['fin', 'debut', 'vu', 'quand'].includes(k) && typeof v === 'number' ? quand(v) : Array.isArray(v) ? v.map(x => (typeof x === 'object' ? Object.values(x).filter(y => y !== null && y !== undefined).join(' ') : x)).join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v));
    const etapes = audit.ia?.corrections?.[c.cle];
    const boutons = [{ texte: 'Fermer', classe: 'flat', valeur: false }];
    if (c.action && admin) {
      boutons.unshift({ texte: ACTION_LIB[c.action.type], classe: c.action.type === 'quarantine' || c.action.type === 'ban' ? 'solid danger' : 'solid', agir: async () => {
        const grave = c.action.type === 'quarantine' || c.action.type === 'ban';
        if (grave && !(await confirmer(`${ACTION_LIB[c.action.type]} de ${c.sujet} ?`, 'L’appareil est coupé du réseau par MapMyLAN. VIGIE garde l’état d’avant : l’action s’annule depuis la page Actions.', { danger: true, oui: ACTION_LIB[c.action.type] }))) return false;
        try { const x = await api.post(`/api/constats/${c.id}/appliquer`, {}); toast(`${ACTION_LIB[x.type]} : ${ETAT_ACTION[x.etat]}${x.resultat ? ` — ${x.resultat}` : ''}.`, x.etat !== 'appliquee'); return true; } catch (e) { toast(e.message, true); return false; }
      } });
    }
    await dialogue({
      titre: c.titre, large: true,
      contenu: [
        h('div', { class: 'filtres mt0' }, chipG(c.gravite), h('span', { class: 'chip', text: domaines[c.domaine] }), h('span', { class: 'chip', text: c.ref }), c.sujet ? h('span', { class: 'chip', text: c.sujet }) : null),
        preuve.length ? h('div', { class: 'bloc' }, h('h3', { text: 'Preuve' }), h('dl', { class: 'preuve' }, preuve.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: valeur(v, k) })]))) : null,
        c.correction ? h('div', { class: 'bloc' }, h('h3', { text: 'Correction proposée' }), h('p', { text: c.correction })) : null,
        etapes?.length ? h('div', { class: 'bloc' }, h('h3', { text: 'Étapes (IA)' }), h('ol', {}, etapes.map(t => h('li', { text: t })))) : null,
        c.ia ? h('div', { class: 'bloc' }, h('h3', { text: 'Relecture de l’IA' }), h('p', { text: `${c.ia.statut === 'confirme' ? 'Confirmé' : c.ia.statut === 'nuance' ? 'Nuancé' : 'Écarté (faux positif probable)'}${c.ia.note ? ` — ${c.ia.note}` : ''}` })) : null,
        c.action && !admin ? h('p', { class: 'hint', text: `Action proposée : ${ACTION_LIB[c.action.type].toLowerCase()} (un administrateur la lance).` }) : null,
      ],
      boutons,
    });
  }
}

// Historique
async function pageHistorique() {
  const audits = await api.get('/api/audits?limite=100');
  const ligne = a => {
    const acts = [
      { texte: 'Voir les constats', agir: () => aller(`constats?audit=${a.id}`) },
      ...(a.statut === 'termine' ? [{ texte: 'Exporter le PDF', agir: () => pdf(a) }] : []),
    ];
    return h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${a.statut === 'echec' ? 'hot' : ''}` }, icone(a.statut === 'echec' ? 'alerte' : 'bouclier', 15)),
      h('div', { class: 'grow1' }, h('strong', { text: quand(a.debut) }),
        h('small', { text: a.statut === 'echec' ? `Échec : ${a.erreur || 'inconnu'}` : a.statut === 'en cours' ? 'en cours…' : `${a.declencheur} · ${a.distribution.critique || 0} critique · ${a.distribution.eleve || 0} élevé · ${a.distribution.faible || 0} faible · ${a.ia?.statut === 'faite' ? `IA ${a.ia.moteur}` : 'sans IA'}` })),
      h('div', { class: 'fin' }, a.score !== null && a.score !== undefined ? h('span', { class: `chip ${a.score >= 80 ? 'g-safe' : a.score >= 60 ? 'g-faible' : a.score >= 40 ? 'g-eleve' : 'g-critique'}`, text: `${a.score} / 100` }) : null,
        h('button', { class: 'btn sm flat', type: 'button', 'aria-label': `Actions pour l’audit du ${quand(a.debut)}`, onclick: sur(() => feuille(`Audit du ${quand(a.debut)}`, acts.map(x => ({ ...x, agir: sur(x.agir) })))) }, icone('actions', 16))));
  };
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Historique' }), h('p', { class: 'lede', text: 'Les 200 derniers audits : manuels, quotidiens, ou lancés par le Hub et MapMyLAN.' })),
      h('div', { class: 'actions' }, membre ? h('button', { class: 'btn solid', type: 'button', onclick: lancerAudit }, icone('jouer', 15), 'Lancer un audit') : null)),
    h('div', { class: 'card' }, audits.length ? audits.map(ligne) : h('p', { class: 'vide', text: 'Aucun audit.' })));
}

// Événements
async function pageEvenements() {
  let tous = false;
  const liste = h('div', {});
  const peindre = async () => {
    const ev = (await api.get('/api/evenements?limite=300')).filter(e => tous || !e.acquitte);
    liste.replaceChildren(...(ev.length ? ev.map(e => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile g-${e.gravite}` }, icone(ICONE_G[e.gravite], 15)),
      h('div', { class: 'grow1' }, h('strong', { text: e.titre }), h('small', { text: [LIB[e.gravite], e.texte, quand(e.quand), e.acquitte ? `acquitté par ${e.acquittePar}` : ''].filter(Boolean).join(' · ') })),
      h('div', { class: 'fin' }, membre && !e.acquitte ? h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { await api.post(`/api/evenements/${e.id}/acquitter`, {}); await peindre(); }) }, 'Acquitter') : null)))
      : [h('p', { class: 'vide', text: tous ? 'Aucun événement.' : 'Rien en attente : tout est acquitté.' })]));
  };
  await peindre();
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Événements' }), h('p', { class: 'lede', text: 'Ce que la veille a remarqué d’une passe à l’autre : nouveaux appareils et ports, signes d’intrusion, trafic suspect, dérives de configuration, sources muettes.' })),
      h('div', { class: 'actions' }, membre ? h('button', { class: 'btn', type: 'button', onclick: sur(async () => { const o = await api.post('/api/veille/passe', {}); toast(o.evenements ? `${pluriel(o.evenements, 'nouvel événement', 'nouveaux événements')}.` : 'Rien de nouveau.'); await peindre(); }) }, icone('oeil', 15), 'Passe de veille') : null)),
    h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Journal de veille' }), h('span', { class: 'note' }, ligneCourte('Voir aussi les acquittés', interrupteur(false, 'Voir aussi les acquittés', async v => { tous = v; await peindre(); })))), liste));
}
const ligneCourte = (t, ctl) => h('span', { class: 'row' }, h('span', { text: t }), ctl);

// Actions
async function pageActions() {
  const liste = h('div', {});
  const peindre = async () => {
    const xs = await api.get('/api/actions').catch(e => { if (e.status === 403) return null; throw e; });
    if (!xs) { liste.replaceChildren(h('p', { class: 'vide', text: 'Réservé aux membres.' })); return; }
    liste.replaceChildren(...(xs.length ? xs.map(x => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${x.etat === 'appliquee' ? 'key' : x.etat === 'echec' ? 'hot' : ''}` }, icone(x.automatique ? 'eclair' : x.type === 'deep-scan' || x.type === 'scan' ? 'oeil' : 'bouclier', 15)),
      h('div', { class: 'grow1' }, h('strong', { text: `${ACTION_LIB[x.type]} · ${x.cibleNom || x.cible}` }),
        h('small', { text: [x.automatique ? 'réaction rapide' : `par ${x.auteur}`, quand(x.quand), x.resultat, x.motif, x.annuleePar ? `annulée par ${x.annuleePar}` : ''].filter(Boolean).join(' · ') })),
      h('div', { class: 'fin' }, h('span', { class: `tag ${x.etat === 'appliquee' ? '' : x.etat === 'echec' ? 'held' : 'idle'}` }, h('i', { class: 'd' }), ETAT_ACTION[x.etat]),
        admin && ['appliquee', 'averifier'].includes(x.etat) && ['quarantine', 'ban'].includes(x.type) ? h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => {
          if (!(await confirmer(`Rendre ${x.cibleNom || x.cible} au réseau ?`, `Il retrouve l’état noté avant l’action (${x.avant.status || 'inconnu'}).`, { oui: 'Rendre au réseau' }))) return;
          await api.post(`/api/actions/${x.id}/annuler`, {}); toast('Appareil rendu au réseau.'); await peindre();
        }) }, 'Annuler') : null)))
      : [h('p', { class: 'vide', text: 'Aucune action. Par défaut, VIGIE propose : rien ne s’exécute sans une personne, sauf la réaction rapide si elle est allumée.' })]));
  };
  await peindre();
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Actions' }), h('p', { class: 'lede', text: 'Chaque action est précédée d’un instantané, vérifiée après coup et défaite si elle n’a pas pris. Elle passe par MapMyLAN, dans les plages qu’il déclare.' })),
      h('div', { class: 'actions' }, membre ? h('button', { class: 'btn', type: 'button', onclick: sur(async () => { await api.post('/api/actions', { type: 'scan' }); toast('Balayage lancé dans MapMyLAN.'); await peindre(); }) }, icone('oeil', 15), 'Balayer le réseau') : null)),
    h('div', { class: 'card' }, liste));
}

// Réglages
async function pageReglages() {
  const r = await api.get('/api/reglages');
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Réglages' }), h('p', { class: 'lede', text: 'IA, veille, réaction rapide, sources et alertes. Le compte et ses facteurs sont dans Sécurité.' }))),
    h('div', { class: 'grille' }, carteIAReglage(r), carteVeille(r), carteReaction(r), carteSourcesReglage(r), carteBilletterie(r), carteTelegram(r)));
}

function carteIAReglage(r) {
  const ia = r.ia;
  const mode = h('select', { class: 'field', 'aria-label': 'Mode' }, Object.entries(MODES_IA).map(([v, t]) => h('option', { value: v, text: t, selected: v === ia.mode })));
  const fournisseur = h('select', { class: 'field', 'aria-label': 'Fournisseur' }, Object.entries(ia.fournisseurs).map(([v, t]) => h('option', { value: v, text: t, selected: v === ia.fournisseur })));
  const modele = h('input', { class: 'field mono', value: ia.modeleCloud, maxlength: 120, placeholder: 'nom du modèle', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Modèle en nuage' });
  const local = h('input', { class: 'field mono', value: ia.modeleLocal, maxlength: 120, placeholder: 'qwen3:8b', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Modèle local' });
  const cle = h('input', { class: 'field mono', type: 'password', placeholder: ia.cle ? 'clé enregistrée — en coller une autre pour la remplacer' : 'clé d’API du fournisseur', autocomplete: 'off', 'aria-label': 'Clé d’API' });
  const appels = h('input', { class: 'field', type: 'number', min: 0, max: 1000, value: ia.appelsJour, 'aria-label': 'Appels par jour' });
  const jetons = h('input', { class: 'field', type: 'number', min: 0, max: 10000000, step: 1000, value: ia.jetonsJour, 'aria-label': 'Jetons par jour' });
  const usage = h('p', { class: 'usage', text: `Aujourd’hui : ${ia.usage.appels} appel${ia.usage.appels > 1 ? 's' : ''} en nuage, ${ia.usage.jetons.toLocaleString('fr-FR')} jetons · ${ia.usageLocal.appels} en local` });
  const essai = cible => sur(async () => { const o = await api.post('/api/reglages/ia/essai', { cible }); toast(`${o.modele} répond (${o.ms} ms).`); });
  return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'IA' }), h('span', { class: 'note', text: ia.mode })), h('div', { class: 'cardbody' },
    h('p', { class: 'hint mt0', text: 'L’IA relit l’audit : elle confirme ou écarte les constats, relie les signaux et rédige la synthèse. Sans elle, l’audit reste complet.' }),
    h('label', { class: 'lbl', text: 'Mode' }), mode,
    h('label', { class: 'lbl mt9', text: `IA locale${ia.localeDisponible ? '' : ' — aucune reliée (installe Ollama depuis le Hub)'}` }), local,
    h('label', { class: 'lbl mt9', text: 'IA en nuage' }), fournisseur, h('div', { class: 'mt9' }, modele), h('div', { class: 'mt9' }, cle),
    h('label', { class: 'lbl mt9', text: 'Appels en nuage par jour' }), appels,
    h('label', { class: 'lbl mt9', text: 'Jetons en nuage par jour' }), jetons, usage,
    h('div', { class: 'actions mt12' },
      h('button', { class: 'btn sm', type: 'button', disabled: !ia.localeDisponible, onclick: essai('locale') }, 'Essai local'),
      h('button', { class: 'btn sm', type: 'button', onclick: essai('cloud') }, 'Essai nuage')),
    h('div', { class: 'actions mt9' },
      h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
        const o = await api.put('/api/reglages/ia', { mode: mode.value, fournisseur: fournisseur.value, modeleCloud: modele.value.trim(), modeleLocal: local.value.trim(), appelsJour: Number(appels.value), jetonsJour: Number(jetons.value), ...(cle.value.trim() ? { cle: cle.value.trim() } : {}) });
        cle.value = ''; cle.placeholder = o.ia.cle ? 'clé enregistrée — en coller une autre pour la remplacer' : 'clé d’API du fournisseur';
        toast('IA enregistrée.');
      }) }, 'Enregistrer'))));
}

function carteVeille(r) {
  const v = r.veille;
  const actif = interrupteur(v.actif, 'Veille');
  const minutes = h('input', { class: 'field', type: 'number', min: 5, max: 1440, value: v.minutes, 'aria-label': 'Minutes entre deux passes' });
  const quotidien = interrupteur(v.auditQuotidien, 'Audit quotidien');
  const heure = h('select', { class: 'field', 'aria-label': 'Heure de l’audit quotidien' }, Array.from({ length: 24 }, (_, i) => h('option', { value: i, text: `${String(i).padStart(2, '0')} h`, selected: i === v.heure })));
  const tls = interrupteur(v.sondeTls, 'Sondes TLS');
  return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Veille' }), h('span', { class: 'note', text: v.actif ? 'active' : 'coupée' })), h('div', { class: 'cardbody' },
    ligneReglage('Veille continue', 'Relit les sources et compare à la passe d’avant : nouveaux appareils et ports, intrusion, trafic suspect, dérives.', actif),
    h('label', { class: 'lbl mt9', text: 'Minutes entre deux passes' }), minutes,
    ligneReglage('Audit quotidien', 'Un audit complet par jour, à l’heure choisie (heure de la machine).', quotidien), heure,
    ligneReglage('Sondes TLS', 'Pendant l’audit : certificat, date d’expiration et protocoles des ports chiffrés du périmètre.', tls),
    h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
      await api.put('/api/reglages/veille', { actif: actif.valeur(), minutes: Number(minutes.value), auditQuotidien: quotidien.valeur(), heure: Number(heure.value), sondeTls: tls.valeur() });
      toast('Veille enregistrée.');
    }) }, 'Enregistrer'))));
}

function carteReaction(r) {
  const x = r.reaction;
  const actif = interrupteur(x.actif, 'Réaction rapide');
  const choisis = new Set(x.types);
  const types = h('div', { class: 'types' }, x.typesPossibles.map(t => {
    const b = h('button', { class: `chip ${choisis.has(t) ? 'a' : ''}`, type: 'button', 'aria-pressed': String(choisis.has(t)), text: t });
    b.addEventListener('click', () => { if (choisis.has(t)) choisis.delete(t); else choisis.add(t); b.classList.toggle('a', choisis.has(t)); b.setAttribute('aria-pressed', String(choisis.has(t))); });
    return b;
  }));
  const parHeure = h('input', { class: 'field', type: 'number', min: 1, max: 20, value: x.parHeure, 'aria-label': 'Isolements par heure' });
  const seuil = h('input', { class: 'field', type: 'number', min: 50, max: 100, value: x.seuil, 'aria-label': 'Seuil de danger' });
  return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Réaction rapide' }), h('span', { class: `note ${x.actif ? 'erreur' : ''}`, text: x.actif ? 'allumée' : 'coupée' })), h('div', { class: 'cardbody' },
    h('p', { class: 'hint mt0', text: 'Sur un signe d’intrusion caractérisé (appareil suspect, hors liste blanche, danger au-delà du seuil), VIGIE met l’appareil en quarantaine seul, puis prévient. Jamais un routeur, un pare-feu, un commutateur, un serveur ni un NAS.' }),
    ligneReglage('Isoler automatiquement', 'Coupé : VIGIE alerte et propose, une personne décide.', actif),
    h('label', { class: 'lbl mt9', text: 'Types d’appareils que VIGIE peut isoler seul' }), types,
    h('label', { class: 'lbl mt9', text: 'Isolements automatiques par heure, au plus' }), parHeure,
    h('label', { class: 'lbl mt9', text: 'Seuil de danger (score MapMyLAN)' }), seuil,
    h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
      if (actif.valeur() && !x.actif && !(await confirmer('Laisser VIGIE isoler seul ?', 'Un appareil qui montre un signe d’intrusion sera coupé du réseau sans attendre personne. Chaque isolement est noté et s’annule depuis Actions.', { danger: true, oui: 'Allumer' }))) return;
      const o = await api.put('/api/reglages/reaction', { actif: actif.valeur(), types: [...choisis], parHeure: Number(parHeure.value), seuil: Number(seuil.value) });
      x.actif = o.reaction.actif;
      toast('Réaction rapide enregistrée.');
    }) }, 'Enregistrer'))));
}

function carteSourcesReglage(r) {
  const jeton = h('input', { class: 'field mono', type: 'password', placeholder: r.docker.jeton ? 'jeton enregistré — en coller un autre pour le remplacer' : 'jeton d’API de docker-control', autocomplete: 'off', 'aria-label': 'Jeton docker-control' });
  const exclus = h('textarea', { class: 'field mono', rows: 3, placeholder: '192.0.2.1\n198.51.100.0/24', 'aria-label': 'Exclusions', spellcheck: 'false' });
  exclus.value = r.perimetre.exclus.join('\n');
  return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Sources et périmètre' })), h('div', { class: 'cardbody' },
    h('p', { class: 'hint mt0', text: `MapMyLAN, NEXARC et SYNAPSE sont reliés par le Hub. docker-control : ${r.docker.url ? 'adresse connue, jeton ci-dessous.' : 'pas installé.'}` }),
    jeton,
    h('label', { class: 'lbl mt12', text: 'Périmètre : plages déclarées dans MapMyLAN' }),
    h('p', { class: 'mono hint mt0', text: r.perimetre.plages.length ? r.perimetre.plages.join(' · ') : 'lues au prochain audit' }),
    h('label', { class: 'lbl mt9', text: 'Exclusions — jamais sondées, jamais isolées (une adresse ou plage par ligne)' }), exclus,
    r.docker.jeton ? h('div', { class: 'actions mt12' }, h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { await api.put('/api/reglages/docker', { retirerJeton: true }); toast('Jeton retiré.'); await aller('reglages'); }) }, 'Retirer le jeton docker-control')) : null,
    h('div', { class: 'actions mt9' },
      h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
        if (jeton.value.trim()) await api.put('/api/reglages/docker', { jeton: jeton.value.trim() });
        await api.put('/api/reglages/perimetre', { exclus: exclus.value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean) });
        jeton.value = '';
        toast('Sources enregistrées.');
      }) }, 'Enregistrer'))));
}

const selSeuil = v => h('select', { class: 'field', 'aria-label': 'À partir de' }, GRAVITES.filter(g => g !== 'safe').reverse().map(g => h('option', { value: g, text: `À partir de « ${LIB[g]} »`, selected: g === v })));

function carteBilletterie(r) {
  const b = r.billetterie;
  const url = h('input', { class: 'field mono', value: b.url, placeholder: 'https://billetterie.exemple/api/tickets', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Adresse' });
  const cle = h('input', { class: 'field mono', type: 'password', placeholder: b.cle ? 'clé enregistrée — en coller une autre' : 'clé d’API', autocomplete: 'off', 'aria-label': 'Clé' });
  const marqueur = h('input', { class: 'field mono', value: b.marqueur, maxlength: 32, 'aria-label': 'Marqueur' });
  const seuil = selSeuil(b.seuil);
  return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Billetterie' }), h('span', { class: `note ${b.etat?.ok === false ? 'erreur' : ''}`, text: b.etat ? (b.etat.ok ? 'dernier envoi reçu' : b.etat.erreur) : b.url ? 'configurée' : 'aucune' })), h('div', { class: 'cardbody' },
    h('p', { class: 'hint mt0', text: 'Aselia ou toute billetterie qui lit le format ticket/v1 (le même que MapMyLAN). Un même incident ne crée qu’un ticket.' }),
    url, h('div', { class: 'mt9' }, cle),
    h('label', { class: 'lbl mt9', text: 'Champ marqueur du ticket' }), marqueur, h('div', { class: 'mt9' }, seuil),
    h('div', { class: 'actions mt12' },
      h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { await api.post('/api/reglages/diffusion/essai', { canal: 'billetterie' }); toast('Ticket d’essai reçu.'); }) }, 'Envoyer un essai')),
    h('div', { class: 'actions mt9' },
      h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
        await api.put('/api/reglages/billetterie', { url: url.value.trim(), marqueur: marqueur.value.trim() || 'ticket', seuil: seuil.value, ...(cle.value.trim() ? { cle: cle.value.trim() } : {}) });
        cle.value = ''; toast('Billetterie enregistrée.');
      }) }, 'Enregistrer'))));
}

function carteTelegram(r) {
  const t = r.telegram;
  const jeton = h('input', { class: 'field mono', type: 'password', placeholder: t.jeton ? 'jeton enregistré — en coller un autre' : 'jeton du bot (@BotFather)', autocomplete: 'off', 'aria-label': 'Jeton du bot' });
  const chat = h('input', { class: 'field mono', value: t.chat, placeholder: 'identifiant du chat', autocomplete: 'off', 'aria-label': 'Chat' });
  const seuil = selSeuil(t.seuil);
  return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Telegram' }), h('span', { class: `note ${t.etat?.ok === false ? 'erreur' : ''}`, text: t.etat ? (t.etat.ok ? 'dernier message parti' : t.etat.erreur) : t.jeton && t.chat ? 'configuré' : 'aucun' })), h('div', { class: 'cardbody' },
    h('p', { class: 'hint mt0', text: 'Envoi seul : aucun bot n’écoute ici. Le bot du Hub peut aussi relayer les déclencheurs de VIGIE par un workflow.' }),
    jeton, h('div', { class: 'mt9' }, chat), h('div', { class: 'mt9' }, seuil),
    h('div', { class: 'actions mt12' },
      h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { await api.post('/api/reglages/diffusion/essai', { canal: 'telegram' }); toast('Message envoyé.'); }) }, 'Envoyer un essai')),
    h('div', { class: 'actions mt9' },
      h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
        await api.put('/api/reglages/telegram', { chat: chat.value.trim(), seuil: seuil.value, ...(jeton.value.trim() ? { jeton: jeton.value.trim() } : {}) });
        jeton.value = ''; toast('Telegram enregistré.');
      }) }, 'Enregistrer'))));
}

aller(location.hash.slice(1) || 'accueil');
setInterval(async () => { try { majRail(await api.get('/api/etat')); } catch { /* déconnecté : la porte s'en charge */ } }, 30000);
