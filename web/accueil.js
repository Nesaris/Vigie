// L'accueil de VIGIE et la page des attaques : d'abord si le réseau est
// vraiment protégé (et, sinon, le chaînon qui manque, avec le bouton qui le
// règle), puis ce qui frappe, d'où, qui est visé, et ce que VIGIE en a fait.
//
// La carte du monde (web/carte-monde.js, 115 Kio) n'est chargée qu'à la
// première page qui la montre.
import { h, icone, toast, confirmer } from '/socle/compte.js';
import { courbe, etincelle, nombre } from '/socle/graphes.js';

const NS = 'http://www.w3.org/2000/svg';
const s = (tag, attrs = {}, ...enfants) => {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) e.setAttribute(k, String(v));
  for (const x of enfants.flat()) if (x) e.append(x);
  return e;
};
const n = v => nombre(v || 0, 0);
const NOMS = new Intl.DisplayNames(['fr'], { type: 'region' });
export function nomPays(cc) {
  if (!cc || cc === '??') return 'Origine inconnue';
  try { return NOMS.of(cc) || cc; } catch { return cc; }
}
const NATURES = { intrusion: 'Intrusion', 'pare-feu': 'Balayage', 'force-brute': 'Force brute', web: 'Attaque web', autre: 'Autre' };
const PERIODES = [[1, '1 h'], [24, '24 h'], [168, '7 jours'], [720, '30 jours']];
const libellePeriode = hrs => (hrs === 1 ? 'la dernière heure' : hrs === 24 ? 'les dernières 24 h' : hrs === 168 ? 'les 7 derniers jours' : 'les 30 derniers jours');
const depuis = t => {
  const m = Math.round((Date.now() - t) / 60e3);
  if (m < 1) return 'à l’instant';
  if (m < 60) return `il y a ${m} min`;
  if (m < 1440) return `il y a ${Math.round(m / 60)} h`;
  return `il y a ${Math.round(m / 1440)} j`;
};
const heure = t => new Date(t).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
const jusqua = t => (t ? new Date(t).toLocaleString('fr-FR', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : 'sans fin');

let monde = null;
const chargerMonde = async () => (monde ||= await import('./carte-monde.js'));

// Une bulle d'information pour toute la page (la même classe que les graphiques du socle).
let bulle = null;
function infobulle(el, lignes) {
  const montrer = e => {
    if (!bulle) { bulle = h('div', { class: 'g-bulle', role: 'tooltip' }); document.body.append(bulle); }
    bulle.replaceChildren(...lignes().map((l, i) => (i ? h('div', { text: l }) : h('b', { text: l }))));
    bulle.hidden = false;
    bulle.style.left = `${Math.max(8, Math.min(e.clientX + 14, innerWidth - bulle.offsetWidth - 8))}px`;
    bulle.style.top = `${Math.max(8, Math.min(e.clientY + 16, innerHeight - bulle.offsetHeight - 8))}px`;
  };
  el.addEventListener('pointermove', montrer);
  el.addEventListener('pointerleave', () => { if (bulle) bulle.hidden = true; });
}

// ── La protection : bloque-t-il vraiment ? ─────────────────────────────────
const NIVEAU = { protege: 'ok', partiel: 'attention', simulation: 'attention', observe: 'attention', emetteur: 'alarme', aveugle: 'alarme' };
const MODE = { actif: 'VIGIE décide seul', simulation: 'simulation : rien n’est envoyé', observer: 'observation seule' };

async function agir(action, p, ctx) {
  if (action.type === 'aller') return ctx.aller(action.page);
  if (!ctx.admin) return toast('Réservé à un administrateur de VIGIE.', true);
  if (action.type === 'emetteur') {
    if (!(await confirmer(`Déclarer ${action.ip} ?`, `VIGIE ne lira plus que les journaux qui viennent de ${action.ip}${p.emetteurs.length ? ` et des émetteurs déjà déclarés (${p.emetteurs.join(', ')})` : ''}, et pourra alors bloquer seul ce qu’ils montrent. Une autre machine du réseau ne pourra plus lui faire bloquer une adresse.`, { oui: 'Déclarer' }))) return;
    await ctx.api.put('/api/reglages/bouclier', { emetteurs: [...new Set([...p.emetteurs, action.ip])] });
    toast(`${action.ip} déclaré : les prochaines menaces seront bloquées.`);
  } else if (action.type === 'mode') {
    if (!(await confirmer('Bloquer pour de vrai ?', 'VIGIE bloquera seul les adresses qui dépassent le seuil, sur la passerelle et chez Cloudflare s’ils sont reliés. Un blocage se lève en un clic.', { oui: 'Activer' }))) return;
    await ctx.api.put('/api/reglages/bouclier', { mode: action.mode });
    toast('Blocage automatique activé.');
  } else if (action.type === 'synchroniser') {
    await ctx.api.post('/api/bouclier/unifi/synchroniser', {});
    toast('Synchronisation relancée.');
  }
  await ctx.recharger();
}

function carteProtection(p, ctx) {
  const niv = NIVEAU[p.niveau] || 'attention';
  const vu = p.emetteursVus[0]?.ip;
  const maillons = [
    { titre: 'Journaux reçus', ok: p.niveau !== 'aveugle', detail: p.niveau === 'aveugle' ? 'rien depuis une heure' : `${n(p.recues)} lignes${p.sondes ? ` · ${p.sondes} sonde${p.sondes > 1 ? 's' : ''}` : ''}` },
    { titre: 'Émetteur déclaré', ok: p.emetteurs.length > 0 || p.sondes > 0, detail: p.emetteurs.length ? p.emetteurs.join(', ') : vu ? `${vu}, non déclaré` : 'aucun' },
    { titre: 'Blocage automatique', ok: p.mode === 'actif', detail: MODE[p.mode] || p.mode },
    { titre: 'Blocages appliqués', ok: (p.passerelle || p.cloudflare) && !p.erreurPasserelle, detail: [p.passerelle && (p.passerelleNom || 'passerelle'), p.cloudflare && 'Cloudflare'].filter(Boolean).join(' · ') || 'rien de relié' },
  ];
  const bouton = p.action ? h('button', { class: `btn ${niv === 'alarme' ? 'solid' : ''}`, type: 'button', onclick: ctx.sur(() => agir(p.action, p, ctx)) }, icone(p.action.type === 'aller' ? 'fleche' : 'bouclier', 15), p.action.libelle) : null;
  return h('div', { class: `card protection niv-${niv}` },
    h('div', { class: 'protection-tete' },
      h('span', { class: 'orbe', 'aria-hidden': 'true' }, h('i'), icone(niv === 'ok' ? 'bouclier' : 'alerte', 20)),
      h('div', { class: 'grow1' }, h('h2', { text: p.titre }), h('p', { text: p.texte })),
      bouton),
    h('ol', { class: 'chaine', 'aria-label': 'Ce qu’il faut pour bloquer' }, maillons.map(m =>
      h('li', { class: m.ok ? 'ok' : 'manque' }, h('span', { class: 'coche', 'aria-hidden': 'true' }, icone(m.ok ? 'verifie' : 'croix', 13)),
        h('div', {}, h('strong', { text: m.titre }), h('small', { text: m.detail }), h('span', { class: 'sr', text: m.ok ? 'en place' : 'manquant' }))))));
}

// ── Les chiffres ────────────────────────────────────────────────────────────
function chiffres(a) {
  const c = a.chiffres, carte = a.carte;
  const part = c.sources ? Math.round(100 * c.arretees / c.sources) : 0;
  const tete = carte.pays.find(p => p.pays !== '??');
  const valeurs = carte.parHeure.map(x => x.n);
  const fig = (titre, valeur, em, delta, extra = null, classe = '') => h('div', { class: `fig ${classe}` }, h('span', { text: titre }), h('strong', {}, valeur, em ? h('em', { text: em }) : null), h('div', { class: 'delta', text: delta }), extra);
  const spark = valeurs.some(Boolean) ? etincelle({ valeurs, largeur: 240, hauteur: 46, classe: 'g-c1' }) : null;
  if (spark) spark.setAttribute('class', 'chart g-etincelle');
  return h('div', { class: 'figs' },
    fig(`Attaques · ${PERIODES.find(x => x[0] === a.heures)?.[1] || a.heures + ' h'}`, n(c.attaques), null, c.attaques ? `${n(Math.round(c.attaques / Math.max(1, a.heures)))} par heure en moyenne` : 'rien vu sur la période', spark),
    fig('Sources', n(c.sources), null, tete ? `surtout ${nomPays(tete.pays)}` : 'adresses distinctes'),
    fig('Arrêtées', c.sources ? `${part}` : '—', c.sources ? '%' : null, c.sources ? `${n(c.arretees)} sources bloquées` : 'aucune source', null, part >= 50 ? 'bon' : c.sources ? 'faible' : ''),
    fig('Bloquées maintenant', n(c.actifs), null, c.signalees ? `${n(c.signalees)} menaces signalées sans blocage` : `${n(c.bloquees + c.simulees)} décisions sur la période`, null, c.signalees ? 'alarme' : ''));
}

// ── La carte du monde ──────────────────────────────────────────────────────
function dessinMonde(pays, { grand = false } = {}) {
  const { PAYS, CENTRES, LARGEUR, HAUTEUR } = monde;
  const max = Math.max(1, ...pays.map(p => p.n));
  const parCode = new Map(pays.map(p => [p.pays, p]));
  const niveau = p => (p ? Math.max(1, Math.ceil(4 * Math.sqrt(p.n / max))) : 0);
  const svg = s('svg', { viewBox: `0 0 ${LARGEUR} ${HAUTEUR}`, class: 'monde', role: 'img', 'aria-label': pays.length ? `Origine des attaques : ${pays.slice(0, 5).map(p => `${nomPays(p.pays)} ${n(p.n)}`).join(', ')}` : 'Aucune attaque sur la période' });
  const terres = s('g', { class: 'terres' });
  for (const [cc, d] of Object.entries(PAYS)) {
    const p = parCode.get(cc);
    const el = s('path', { d, class: `terre${p ? ` touche n${niveau(p)}` : ''}` });
    if (p) infobulle(el, () => [nomPays(cc), `${n(p.n)} coup${p.n > 1 ? 's' : ''} · ${n(p.sources)} source${p.sources > 1 ? 's' : ''}`, p.bloquees ? `${n(p.bloquees)} bloquée${p.bloquees > 1 ? 's' : ''}` : 'aucune bloquée']);
    terres.append(el);
  }
  const impacts = s('g', { class: 'impacts' });
  pays.filter(p => CENTRES[p.pays]).slice(0, grand ? 40 : 25).reverse().forEach((p, i, l) => {
    const [x, y] = CENTRES[p.pays];
    const r = 2.5 + (grand ? 16 : 13) * Math.sqrt(p.n / max);
    const g = s('g', { class: 'impact' });
    // Les trois premières origines battent doucement (sauf mouvement réduit).
    if (i >= l.length - 3) g.append(s('circle', { cx: x, cy: y, r, class: 'onde' }));
    g.append(s('circle', { cx: x, cy: y, r, class: 'halo' }), s('circle', { cx: x, cy: y, r: Math.min(2.6, r / 2), class: 'coeur' }));
    infobulle(g, () => [nomPays(p.pays), `${n(p.n)} coup${p.n > 1 ? 's' : ''} · ${n(p.sources)} source${p.sources > 1 ? 's' : ''}`, p.bloquees ? `${n(p.bloquees)} bloquée${p.bloquees > 1 ? 's' : ''}` : 'aucune bloquée']);
    impacts.append(g);
  });
  svg.append(terres, impacts);
  return h('div', { class: `monde-boite${grand ? ' grand' : ''}` }, svg);
}

function listePays(pays, total, limite) {
  if (!pays.length) return h('p', { class: 'vide', text: 'Aucune attaque vue sur la période.' });
  const max = Math.max(1, ...pays.map(p => p.n));
  return h('ol', { class: 'origines' }, pays.slice(0, limite).map(p => {
    const barre = h('i');
    barre.style.width = `${Math.max(2, 100 * p.n / max)}%`;
    return h('li', {},
      h('span', { class: 'code', text: p.pays === '??' ? '··' : p.pays }),
      h('div', { class: 'grow1' }, h('div', { class: 'ligne-tete' }, h('strong', { text: nomPays(p.pays) }), h('b', { text: n(p.n) })),
        h('div', { class: 'bar' }, barre),
        h('small', { text: `${n(p.sources)} source${p.sources > 1 ? 's' : ''} · ${total ? Math.round(100 * p.n / total) : 0} % du total${p.bloquees ? ` · ${n(p.bloquees)} bloquée${p.bloquees > 1 ? 's' : ''}` : ''}` })));
  }));
}

// ── Pays → machines visées ─────────────────────────────────────────────────
function dessinFlux(liens, nomCible) {
  if (!liens.length) return h('p', { class: 'vide', text: 'Les liaisons apparaissent quand une attaque vise une machine connue.' });
  const totalG = new Map(), totalD = new Map();
  for (const l of liens) { totalG.set(l.pays, (totalG.get(l.pays) || 0) + l.n); totalD.set(l.cible, (totalD.get(l.cible) || 0) + l.n); }
  const gauche = [...totalG].sort((a, b) => b[1] - a[1]).slice(0, 6), droite = [...totalD].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const L = 960, pas = 44, H = Math.max(gauche.length, droite.length) * pas + 8;
  const yG = new Map(gauche.map(([k], i) => [k, 4 + pas / 2 + i * pas * (Math.max(gauche.length, droite.length) / gauche.length)]));
  const yD = new Map(droite.map(([k], i) => [k, 4 + pas / 2 + i * pas * (Math.max(gauche.length, droite.length) / droite.length)]));
  const max = Math.max(1, ...liens.map(l => l.n));
  const x0 = 230, x1 = L - 230;
  const svg = s('svg', { viewBox: `0 0 ${L} ${H}`, class: 'flux', role: 'img', 'aria-label': liens.slice(0, 6).map(l => `${nomPays(l.pays)} vers ${nomCible(l.cible)} : ${n(l.n)}`).join(', ') });
  const g = s('g', { class: 'liens' });
  for (const l of liens) {
    if (!yG.has(l.pays) || !yD.has(l.cible)) continue;
    const a = yG.get(l.pays), b = yD.get(l.cible), m = (x0 + x1) / 2;
    const p = s('path', { d: `M${x0} ${a}C${m} ${a} ${m} ${b} ${x1} ${b}`, class: 'lien' });
    p.style.strokeWidth = `${1.2 + 9 * Math.sqrt(l.n / max)}`;
    infobulle(p, () => [`${nomPays(l.pays)} → ${nomCible(l.cible)}`, `${n(l.n)} coup${l.n > 1 ? 's' : ''}`]);
    g.append(p);
  }
  svg.append(g);
  for (const [k, v] of gauche) {
    const y = yG.get(k);
    svg.append(s('circle', { cx: x0, cy: y, r: 4, class: 'noeud' }), s('text', { x: x0 - 12, y: y - 3, 'text-anchor': 'end', class: 'nom' }, document.createTextNode(nomPays(k))), s('text', { x: x0 - 12, y: y + 12, 'text-anchor': 'end', class: 'val' }, document.createTextNode(n(v))));
  }
  for (const [k, v] of droite) {
    const y = yD.get(k);
    svg.append(s('circle', { cx: x1, cy: y, r: 4, class: 'noeud cible' }), s('text', { x: x1 + 12, y: y - 3, class: 'nom' }, document.createTextNode(nomCible(k).slice(0, 26))), s('text', { x: x1 + 12, y: y + 12, class: 'val' }, document.createTextNode(n(v))));
  }
  return h('div', { class: 'flux-boite' }, svg);
}

// ── Listes ─────────────────────────────────────────────────────────────────
const nomCibleDe = carte => {
  const noms = new Map(carte.cibles.filter(c => c.nom).map(c => [c.cible, c.nom]));
  return c => noms.get(c) || c;
};
function listeCibles(carte, limite) {
  if (!carte.cibles.length) return h('p', { class: 'vide', text: 'Aucune machine visée sur la période.' });
  return h('div', {}, carte.cibles.slice(0, limite).map(c => h('div', { class: 'flowrow' },
    h('span', { class: 'itile' }, icone('serveur', 15)),
    h('div', { class: 'grow1' }, h('strong', { text: c.nom || c.cible }), h('small', { text: [c.nom ? c.cible : null, c.natures.map(x => NATURES[x] || x).join(', '), `${n(c.sources)} source${c.sources > 1 ? 's' : ''}`].filter(Boolean).join(' · ') })),
    h('b', { class: 'compte', text: n(c.n) }))));
}
const ETAT_B = { actif: ['bloquée', 'g-critique'], simule: ['aurait bloqué', 'g-faible'], expire: ['expirée', ''], leve: ['levée', ''] };
function listeBlocages(blocages, pays) {
  if (!blocages.length) return h('p', { class: 'vide', text: 'VIGIE n’a encore rien bloqué.' });
  return h('div', {}, blocages.map(b => {
    const [lib, cl] = ETAT_B[b.etat] || [b.etat, ''];
    return h('div', { class: 'flowrow' },
      h('span', { class: `itile ${b.etat === 'actif' ? 'g-critique' : ''}` }, icone('muraille', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'mono', text: b.ip }), h('small', { text: `${pays(b.ip)} · ${b.motif || 'menace'}` })),
      h('div', { class: 'fin-col' }, h('span', { class: `chip ${cl}`, text: lib }), h('small', { text: b.etat === 'actif' ? `jusqu’à ${jusqua(b.fin)}` : depuis(b.debut) })));
  }));
}
const RANG_G = { critique: 0, eleve: 1, faible: 2, info: 3 };
function listeAFaire(items, ctx, p) {
  if (!items.length) return h('div', { class: 'tout-va' }, h('span', { class: 'itile g-safe' }, icone('verifie', 15)), h('div', {}, h('strong', { text: 'Rien à faire' }), h('small', { text: 'VIGIE s’occupe du reste et préviendra si quelque chose demande quelqu’un.' })));
  return h('div', {}, [...items].sort((a, b) => (RANG_G[a.gravite] ?? 4) - (RANG_G[b.gravite] ?? 4)).map(x => h('div', { class: 'flowrow' },
    h('span', { class: `itile g-${x.gravite}` }, icone(x.gravite === 'critique' ? 'eclair' : 'alerte', 15)),
    h('div', { class: 'grow1' }, h('strong', { text: x.titre }), x.texte ? h('small', { text: x.texte }) : null),
    x.action ? h('button', { class: 'btn sm', type: 'button', onclick: ctx.sur(() => agir(x.action, p, ctx)) }, x.action.libelle) : null)));
}

function carte(titre, note, corps, { plus = null, classe = '' } = {}) {
  return h('div', { class: `card ${classe}` },
    h('header', {}, h('h2', { text: titre }), note ? h('span', { class: 'note', text: note }) : null, plus),
    corps);
}
const boutonPlus = (ctx, page, texte = 'Afficher plus') => h('button', { class: 'btn sm flat', type: 'button', onclick: () => ctx.aller(page) }, texte, icone('fleche', 14));

// ── L'accueil ──────────────────────────────────────────────────────────────
export async function pageAccueil(ctx) {
  const boite = h('div', { class: 'page accueil' });
  const peindre = async () => {
    const [a] = await Promise.all([ctx.api.get('/api/accueil?heures=24'), chargerMonde()]);
    ctx.majRail?.(a);
    const nomCible = nomCibleDe(a.carte);
    const paysIp = new Map(a.carte.top.map(t => [t.ip, t.pays]));
    const paysDe = ip => nomPays(paysIp.get(ip));
    boite.replaceChildren(
      h('div', { class: 'headrow' },
        h('div', {}, h('h1', { class: 'title', text: 'Votre réseau' }), h('p', { class: 'lede', text: `Les dernières 24 h · à jour à ${heure(a.maintenant)}${a.geo.blocs ? '' : ' · pays d’origine dès que les registres sont téléchargés'}` })),
        h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: () => ctx.aller('attaques') }, icone('radar', 15), 'Carte des attaques'))),
      carteProtection(a.protection, { ...ctx, recharger: peindre }),
      chiffres(a),
      carte('D’où viennent les attaques', `${n(a.carte.pays.filter(p => p.pays !== '??').length)} pays`,
        h('div', { class: 'monde-split' }, dessinMonde(a.carte.pays), listePays(a.carte.pays, a.carte.total, 5)),
        { plus: boutonPlus(ctx, 'attaques') }),
      h('div', { class: 'colonnes' },
        h('div', { class: 'colonne' }, carte('À faire', a.aFaire.length ? `${a.aFaire.length}` : null, listeAFaire(a.aFaire, { ...ctx, recharger: peindre }, a.protection), { classe: 'carte-pleine' })),
        h('div', { class: 'colonne' }, carte('Machines visées', null, listeCibles(a.carte, 5), { plus: a.carte.cibles.length > 5 ? boutonPlus(ctx, 'attaques') : null, classe: 'carte-pleine' }))),
      carte('Ce que VIGIE a fait', `${n(a.chiffres.actifs)} en cours`, listeBlocages(a.blocages.slice(0, 5), paysDe), { plus: boutonPlus(ctx, 'bouclier', 'Tout le bouclier') }));
  };
  await peindre();
  ctx.suivre(peindre, 20_000);
  return boite;
}

// ── La page des attaques (carte en grand) ──────────────────────────────────
export async function pageAttaques(ctx, params) {
  let heures = Number(params?.get('heures')) || 24;
  if (!PERIODES.some(p => p[0] === heures)) heures = 24;
  const boite = h('div', { class: 'page attaques' });
  const vues = h('div', { class: 'views', role: 'tablist', 'aria-label': 'Période' }, PERIODES.map(([v, t]) =>
    h('button', { class: 'view', type: 'button', role: 'tab', dataset: { v }, onclick: () => { heures = v; history.replaceState(null, '', `#attaques?heures=${v}`); peindre().catch(e => toast(e.message, true)); } }, t)));
  const peindre = async () => {
    const [a] = await Promise.all([ctx.api.get(`/api/accueil?heures=${heures}`), chargerMonde()]);
    for (const b of vues.children) { const on = Number(b.dataset.v) === heures; b.classList.toggle('on', on); b.setAttribute('aria-selected', String(on)); }
    const c = a.carte;
    const nomCible = nomCibleDe(c);
    const etiquettes = c.parHeure.map(x => (heures <= 24 ? heure(x.heure) : new Date(x.heure).toLocaleDateString('fr-FR', { day: 'numeric', month: 'short' })));
    const barres = (l, lib) => h('div', { class: 'barres' }, l.map(x => {
      const i = h('i'); i.style.width = `${Math.max(2, 100 * x.n / Math.max(1, ...l.map(y => y.n)))}%`;
      return h('div', { class: 'barre-l' }, h('div', { class: 'ligne-tete' }, h('span', { text: lib(x) }), h('b', { text: n(x.n) })), h('div', { class: 'bar' }, i));
    }));
    boite.replaceChildren(
      h('div', { class: 'headrow' },
        h('div', {}, h('h1', { class: 'title', text: 'Attaques' }), h('p', { class: 'lede', text: `Ce qui a frappé le réseau depuis Internet sur ${libellePeriode(heures)}. Pays d’enregistrement du réseau source, d’après les registres d’Internet.` })),
        h('div', { class: 'actions' }, vues)),
      chiffres(a),
      carte('Carte des attaques', `${n(c.pays.filter(p => p.pays !== '??').length)} pays · ${n(c.sources)} sources`,
        h('div', { class: 'monde-split grand' }, dessinMonde(c.pays, { grand: true }), listePays(c.pays, c.total, 10))),
      carte('Qui attaque qui', 'pays d’origine → machine visée', dessinFlux(c.liens, nomCible)),
      carte('Au fil du temps', heures <= 24 ? 'par heure' : 'par heure, sur la période',
        c.total ? h('div', { class: 'pad' }, courbe({ series: [{ nom: 'Coups', valeurs: c.parHeure.map(x => x.n) }], etiquettes: etiquettes.filter((_, i, l) => i % Math.ceil(l.length / 6) === 0), hauteur: 180, libelle: 'Attaques par heure', legende: false, format: v => n(v) })) : h('p', { class: 'vide', text: 'Rien sur la période.' })),
      h('div', { class: 'colonnes' },
        h('div', { class: 'colonne' }, carte('Sources les plus actives', `${Math.min(15, c.top.length)} sur ${n(c.sources)}`, listeSources(c.top.slice(0, 15), ctx, peindre), { classe: 'carte-pleine' })),
        h('div', { class: 'colonne' },
          carte('Machines visées', null, listeCibles(c, 8)),
          carte('Nature', null, c.natures.length ? h('div', { class: 'pad' }, barres(c.natures, x => NATURES[x.nature] || x.nature)) : h('p', { class: 'vide', text: 'Rien sur la période.' })),
          carte('Ports visés', null, c.ports.length ? h('div', { class: 'pad' }, barres(c.ports.slice(0, 6), x => `port ${x.port}`)) : h('p', { class: 'vide', text: 'Aucun port relevé.' }), { classe: 'carte-pleine' }))));
  };
  await peindre();
  ctx.suivre(peindre, 30_000);
  return boite;
}

function listeSources(top, ctx, peindre) {
  if (!top.length) return h('p', { class: 'vide', text: 'Aucune source sur la période.' });
  return h('div', {}, top.map(t => h('div', { class: 'flowrow' },
    h('span', { class: 'code', text: t.pays && t.pays !== '??' ? t.pays : '··' }),
    h('div', { class: 'grow1' }, h('strong', { class: 'mono', text: t.ip }), h('small', { text: `${nomPays(t.pays)} · ${t.natures.map(x => NATURES[x] || x).join(', ')} · ${depuis(t.derniere)}` })),
    h('div', { class: 'fin-col' }, h('b', { class: 'compte', text: n(t.n) }),
      t.bloquee ? h('span', { class: 'chip g-critique', text: 'bloquée' })
        : ctx.admin ? h('button', { class: 'btn sm', type: 'button', onclick: ctx.sur(async () => {
          if (!(await confirmer(`Bloquer ${t.ip} ?`, 'L’adresse est envoyée à la passerelle (et à Cloudflare s’il est relié) pour la durée prévue par le bouclier.', { oui: 'Bloquer', danger: true }))) return;
          await ctx.api.post('/api/bouclier/bloquer', { ip: t.ip, motif: 'bloquée depuis la carte des attaques' });
          toast(`${t.ip} bloquée.`);
          await peindre();
        }) }, 'Bloquer') : null))));
}
