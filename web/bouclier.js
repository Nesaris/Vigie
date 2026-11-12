// Page Bouclier : ce que la passerelle et les listes de menaces voient, ce que
// VIGIE bloque, et le branchement (UniFi, syslog, listes, export). La partie
// vivante se repeint toutes les quinze secondes ; les réglages, une fois.
//
// Rien n'est injecté comme balisage : tout passe par h(), qui écrit du texte.
import { h, icone, toast, confirmer, dialogue } from '/socle/compte.js';

const MODES = {
  observer: 'Observer — signale, ne bloque rien',
  simulation: 'Simulation — note ce qu’il aurait bloqué',
  actif: 'Actif — bloque seul les adresses extérieures',
};
const ETAT = { actif: 'bloquée', simule: 'simulée', leve: 'levée', expire: 'expirée' };
const DUREES = [['', 'Durée selon les récidives'], ['60', '1 heure'], ['1440', '1 jour'], ['10080', '7 jours'], ['43200', '30 jours'], ['525600', '1 an']];

const duree = ms => {
  if (ms <= 0) return 'échue';
  const m = Math.round(ms / 60e3);
  if (m < 60) return `${m} min`;
  if (m < 2880) return `${Math.round(m / 60)} h`;
  return `${Math.round(m / 1440)} j`;
};
const depuis = t => (!t ? 'jamais' : Date.now() - t < 60e3 ? 'à l’instant' : `il y a ${duree(Date.now() - t)}`);
const lignes = v => v.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
const barre = (score, seuil) => {
  const b = h('div', { class: 'bar menace-barre' }, h('i'));
  b.firstChild.style.width = `${Math.min(100, Math.round(score / seuil * 100))}%`;
  b.firstChild.className = score >= seuil ? 's-mauvais' : score >= seuil / 2 ? 's-faible' : 's-moyen';
  return b;
};

export async function pageBouclier({ api, admin, sur, quand, interrupteur, suivre, recharger, aller, params = null }) {
  let etat = await api.get('/api/bouclier');
  const reglages = admin ? (await api.get('/api/reglages')).bouclier : null;

  const lede = h('p', { class: 'lede' });
  const figs = h('div', { class: 'figs' });
  const avis = h('div', {});
  const menaces = h('div', {});
  const blocages = h('div', {});
  const alertes = h('div', {});
  const internes = h('div', {});
  let tousBlocages = false;

  const bloquer = (ip = '') => sur(async () => {
    const champ = h('input', { class: 'field mono', value: ip, placeholder: '203.0.113.7 ou 2001:db8::7', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Adresse' });
    const temps = h('select', { class: 'field mt9', 'aria-label': 'Durée' }, DUREES.map(([v, t]) => h('option', { value: v, text: t })));
    const motif = h('input', { class: 'field mt9', maxlength: 200, placeholder: 'motif (facultatif)', 'aria-label': 'Motif' });
    const fait = await dialogue({
      titre: 'Bloquer une adresse', texte: 'Une adresse publique seulement : VIGIE refuse le réseau local, les résolveurs DNS publics, Cloudflare et la liste blanche.',
      contenu: [champ, temps, motif],
      boutons: [{ texte: 'Annuler', classe: 'flat', valeur: false }, { texte: 'Bloquer', classe: 'danger solid', agir: async () => {
        try {
          await api.post('/api/bouclier/bloquer', { ip: champ.value.trim(), ...(temps.value ? { minutes: Number(temps.value) } : {}), ...(motif.value.trim() ? { motif: motif.value.trim() } : {}) });
          return true;
        } catch (e) { toast(e.message, true); return false; }
      } }],
    });
    if (fait) { toast('Adresse bloquée.'); await peindre(); }
  })();

  // L'essentiel sur une page : les chiffres, les avis, cinq lignes par liste.
  // Chaque liste a sa propre page (#bouclier?vue=menaces…), hors du menu,
  // avec un retour ; les réglages aussi. Les listes longues se déplient.
  const TITRES = { menaces: 'Menaces extérieures', blocages: 'Blocages', machines: 'Machines du réseau', alertes: 'Alertes de l’IPS', reglages: 'Réglages du bouclier' };
  const vue = TITRES[params?.get?.('vue')] ? params.get('vue') : 'ensemble';
  const deplie = {};
  const apercus = { menaces: h('div', {}), blocages: h('div', {}), machines: h('div', {}), alertes: h('div', {}) };
  const compteurs = {};
  const ouvrir = k => aller(`bouclier?vue=${k}`);
  const voirPlus = k => { const b = h('button', { class: 'btn sm flat', type: 'button', onclick: () => ouvrir(k) }, 'Tout voir'); return b; };
  const borner = (k, lignes, n = 50) => {
    if (lignes.length <= n || deplie[k]) return lignes;
    return [...lignes.slice(0, n), h('div', { class: 'pad-bas' }, h('button', { class: 'btn sm', type: 'button', onclick: () => { deplie[k] = true; peindre_(); } }, `Voir les ${lignes.length - n} autres`))];
  };
  const apercu = (k, lignes, vide) => { apercus[k].replaceChildren(...(lignes.length ? lignes.slice(0, 5) : [vide.cloneNode(true)])); compteurs[k] = lignes.length; };
  const liens = h('div', { class: 'actions liens-detail' });

  function peindre_() {
    const e = etat;
    const maintenant = Date.now();
    const actifs = e.blocages.filter(b => ['actif', 'simule'].includes(b.etat) && (!b.fin || b.fin > maintenant));
    const bloquees = new Set(actifs.map(b => b.ip));
    const releve = e.passerelle?.releve || {};
    const recues = e.syslog.lues + e.sondes.reduce((a, s) => a + s.lues, 0) + (releve.derniere ? 1 : 0);
    lede.textContent = `${MODES[e.mode]} · seuil ${e.seuil} · ${e.listes.filter(l => l.active && l.entrees).length} listes de menaces chargées`;

    const fig = (titre, valeur, detail, ic, chaud = false, cible = null) => h('div', { class: `fig ${cible ? 'cliquable' : ''}`, ...(cible ? { role: 'button', tabindex: 0, onclick: () => ouvrir(cible), onkeydown: ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); ouvrir(cible); } } } : {}) },
      h('div', { class: `tile ${chaud ? 'warn' : ''}` }, icone(ic, 15)), h('span', { text: titre }), h('strong', { text: String(valeur) }), h('div', { class: 'delta', text: detail }));
    const suspectes = e.internes.filter(x => x.score >= x.seuil / 2);
    figs.replaceChildren(
      fig('Bloquées', e.actifs, e.mode === 'actif' ? 'sur la passerelle et la liste' : `mode ${e.mode}`, 'bouclier', e.actifs > 0, 'blocages'),
      fig('Menaces suivies', e.menaces.length, e.menaces[0] ? `la plus haute : ${e.menaces[0].score}` : 'aucune adresse notée', 'oeil', false, 'menaces'),
      fig('Alertes IPS', e.compteurs.ips || 0, `${(e.compteurs['pare-feu'] || 0).toLocaleString('fr-FR')} lignes de pare-feu`, 'eclair', (e.compteurs.ips || 0) > 0, 'alertes'),
      fig('Machines suspectes', suspectes.length, 'du réseau local', 'alerte', e.internes.some(x => x.score >= x.seuil), 'machines'));

    const notes = [];
    if (!recues) notes.push(['warn', 'Rien reçu de la passerelle pour l’instant : ni journal, ni relève par MapMyLAN. Voir « Passerelle » et « Journaux de la passerelle » dans Réglages.']);
    else if (releve.active && !e.syslog.lues) notes.push(['', 'Alertes de l’IPS relevées par MapMyLAN chaque minute. Pour voir aussi les refus du pare-feu et le pot de miel, envoie les journaux de la passerelle (Réglages → Journaux).']);
    else if (e.syslog.derniere && maintenant - e.syslog.derniere > 30 * 60e3) notes.push(['warn', `Plus aucun journal de la passerelle depuis ${duree(maintenant - e.syslog.derniere)}.`]);
    if (e.syslog.lues && !e.syslog.emetteursDeclares) notes.push(['warn', 'Toute adresse privée peut envoyer des journaux à VIGIE : tant que la passerelle n’est pas déclarée, ce qu’ils disent est signalé, jamais bloqué ni isolé seul. Déclare-la dans Réglages → « Liste blanche et émetteurs ».']);
    if (!e.unifi.relie) notes.push(['', 'Aucune passerelle reliée : les blocages restent dans VIGIE et dans la liste exportée, rien n’est coupé à la frontière. Relie le routeur dans MapMyLAN : VIGIE s’en servira seule.']);
    else if (e.unifi.ok === false) notes.push(['warn', `La passerelle ne reçoit plus les blocages : ${e.unifi.erreur}`]);
    else if (e.unifi.regles && !e.unifi.regles.erreur && (!e.unifi.regles.entrant || !e.unifi.regles.sortant)) notes.push(['warn', `Listes envoyées, mais ${!e.unifi.regles.entrant && !e.unifi.regles.sortant ? 'aucune règle du pare-feu ne les cite' : `la règle ${!e.unifi.regles.entrant ? 'd’entrée' : 'de sortie'} manque`} : elles ne bloquent rien tant que les règles ne sont pas posées (Réglages → Passerelle).`]);
    if (e.mode !== 'actif') notes.push(['', e.mode === 'observer' ? 'Mode observation : VIGIE signale, ne bloque rien.' : 'Mode simulation : VIGIE note ce qu’il aurait bloqué, rien ne part vers la passerelle.']);
    if (e.tempete && maintenant - e.tempete.quand < 10 * 60e3) notes.unshift(['warn', `Tempête en cours sur le port ${e.tempete.port} : ${e.tempete.sources} adresses, ${e.tempete.parMinute} paquets en une minute. Les plus bruyantes sont bloquées${e.cloudflare?.attaque ? ', Cloudflare est en mode Under Attack' : ''} ; au-delà, c’est Cloudflare ou le fournisseur d’accès.`]);
    else if (e.cloudflare?.attaque) notes.unshift(['warn', `Cloudflare en mode Under Attack (${e.cloudflare.attaque.motif}) jusqu’à ${quand(e.cloudflare.attaque.jusqua)}.`]);
    avis.replaceChildren(...notes.slice(0, 1).map(([c, t]) => h('div', { class: 'card' }, h('div', { class: 'notice' }, h('span', { class: `itile ${c ? 'g-eleve' : 'g-info'}` }, icone(c ? 'alerte' : 'oeil', 15)), h('div', {}, h('p', { text: t }))))));

    const ligneMenace = m => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${m.score >= m.seuil ? 'g-critique' : m.score >= m.seuil / 2 ? 'g-eleve' : 'g-faible'}` }, icone('oeil', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: m.ip }),
        barre(m.score, m.seuil),
        h('small', { text: `${m.score} / ${m.seuil} · ${m.raisons.slice(0, 3).map(r => r.n > 1 ? `${r.texte} (×${r.n})` : r.texte).join(' · ')}` }),
        h('small', { text: `vue ${m.vu} fois · dernière ${depuis(m.dernier)}` })),
      h('div', { class: 'fin' }, bloquees.has(m.ip) ? h('span', { class: 'tag held' }, h('i', { class: 'd' }), 'bloquée')
        : admin ? h('button', { class: 'btn sm', type: 'button', onclick: () => bloquer(m.ip) }, 'Bloquer') : null));
    const videMenaces = h('p', { class: 'vide', text: 'Aucune adresse extérieure notée. Elles apparaissent ici dès qu’une alerte, un balayage ou une liste de menaces les signale.' });
    menaces.replaceChildren(...(e.menaces.length ? borner('menaces', e.menaces.map(ligneMenace)) : [videMenaces]));
    const courteMenace = m => h('div', { class: 'ligne-courte' },
      h('span', { class: `pastille g-${m.score >= m.seuil ? 'critique' : m.score >= m.seuil / 2 ? 'eleve' : 'faible'}` }),
      h('strong', { class: 'ip', text: m.ip }), h('span', { class: 'tronque', text: (m.raisons[0]?.texte || '').replace(/^IPS : /, '') }),
      bloquees.has(m.ip) ? h('span', { class: 'tag held' }, h('i', { class: 'd' }), 'bloquée') : h('b', { class: 'mono', text: String(m.score) }));
    apercu('menaces', e.menaces.map(courteMenace), videMenaces);

    const ligneBlocage = b => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${b.etat === 'actif' ? 'g-critique' : ''}` }, icone(b.automatique ? 'eclair' : 'bouclier', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: b.ip }),
        h('span', { class: `tag ${['actif', 'simule'].includes(b.etat) ? (b.etat === 'actif' ? 'held' : 'warn') : 'idle'}` }, h('i', { class: 'd' }),
          ['actif', 'simule'].includes(b.etat) ? `${ETAT[b.etat]} · ${b.fin ? `encore ${duree(b.fin - maintenant)}` : 'sans fin'}` : `${ETAT[b.etat] || b.etat}${b.leve_par ? ` par ${b.leve_par}` : ''}`),
        h('small', { text: [b.automatique ? 'VIGIE' : `par ${b.auteur}`, quand(b.debut), b.recidive ? `récidive n° ${b.recidive}` : ''].filter(Boolean).join(' · ') }),
        h('small', { text: b.raisons.slice(0, 3).join(' · ') || b.motif })),
      h('div', { class: 'fin' },
        admin && ['actif', 'simule'].includes(b.etat) ? h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => {
          if (!(await confirmer(`Lever le blocage de ${b.ip} ?`, 'L’adresse sort de la liste de la passerelle à la prochaine synchronisation (quelques secondes). Une récidive la bloquera plus longtemps.', { oui: 'Lever' }))) return;
          await api.post(`/api/bouclier/blocages/${b.id}/lever`, {}); toast('Blocage levé.'); await peindre();
        }) }, 'Lever') : null));
    const montres = tousBlocages ? e.blocages : actifs;
    blocages.replaceChildren(...(montres.length ? borner('blocages', montres.map(ligneBlocage)) : [h('p', { class: 'vide', text: tousBlocages ? 'Aucun blocage.' : 'Aucune adresse bloquée en ce moment.' })]));
    compteurs.blocages = actifs.length;

    const ligneAlerte = a => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${a.gravite === 1 ? 'g-critique' : a.gravite === 2 ? 'g-eleve' : 'g-faible'}` }, icone('eclair', 15)),
      h('div', { class: 'grow1' }, h('strong', { text: a.signature || 'alerte' }),
        h('small', { class: 'mono', text: `${a.src || '?'} → ${a.dst || '?'}${a.dport ? `:${a.dport}` : ''}` }),
        h('small', { text: [a.categorie, a.capteur, quand(a.quand)].filter(Boolean).join(' · ') })),
      h('div', { class: 'fin' }, h('span', { class: `tag ${a.action === 'bloque' ? '' : 'warn'}` }, h('i', { class: 'd' }), a.action === 'bloque' ? 'coupée par l’IPS' : `gravité ${a.gravite}`)));
    const videAlertes = h('p', { class: 'vide', text: 'Aucune alerte d’IPS reçue. Sur la passerelle UniFi : CyberSecure → Intrusion Prevention activé, et la catégorie « Intrusion Prevention » envoyée au serveur SIEM.' });
    alertes.replaceChildren(...(e.alertes.length ? borner('alertes', e.alertes.map(ligneAlerte)) : [videAlertes]));
    compteurs.alertes = e.alertes.length;

    const ligneInterne = m => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${m.score >= m.seuil ? 'g-critique' : 'g-eleve'}` }, icone('alerte', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: m.ip }), barre(m.score, m.seuil),
        h('small', { text: m.raisons.slice(0, 3).map(r => r.texte).join(' · ') })),
      h('div', { class: 'fin' }, h('span', { class: 'note', text: `${m.score} / ${m.seuil}` })));
    const videInternes = h('p', { class: 'vide', text: 'Aucune machine du réseau ne se comporte comme une machine compromise.' });
    internes.replaceChildren(...(e.internes.length ? borner('machines', e.internes.map(ligneInterne)) : [videInternes]));
    const courteInterne = m => h('div', { class: 'ligne-courte' },
      h('span', { class: `pastille g-${m.score >= m.seuil ? 'critique' : 'eleve'}` }),
      h('strong', { class: 'ip', text: m.ip }), h('span', { class: 'tronque', text: (m.raisons[0]?.texte || '').replace(/^IPS, vers \S+ \(réseau interne\) : |^IPS : /, '') }),
      h('b', { class: 'mono', text: `${m.score}` }));
    apercu('machines', e.internes.map(courteInterne), videInternes);
    liens.replaceChildren(
      h('button', { class: 'btn sm', type: 'button', onclick: () => ouvrir('blocages') }, icone('bouclier', 14), `Blocages en cours · ${actifs.length}`),
      h('button', { class: 'btn sm', type: 'button', onclick: () => ouvrir('alertes') }, icone('eclair', 14), `Alertes de l’IPS · ${e.alertes.length}`));
    // Les notes d'en-tête des aperçus : le compte, et le reste à voir.
    for (const [k, el] of Object.entries(apercus)) { const n = compteurs[k] || 0; const note = el.parentElement?.querySelector('.note-apercu'); if (note) note.textContent = n > 5 ? `5 sur ${n}` : n ? `${n}` : ''; }
  }
  async function peindre() { etat = await api.get('/api/bouclier'); peindre_(); }
  suivre(peindre, 15000);

  const carte = (titre, note, corps) => h('div', { class: 'card' }, h('header', {}, h('h2', { text: titre }), note), corps);
  const carteApercu = (k, titre) => h('div', { class: 'card' }, h('header', {}, h('h2', { text: titre }), h('span', { class: 'row' }, h('span', { class: 'note note-apercu' }), voirPlus(k))), apercus[k]);
  const retour = h('button', { class: 'btn sm flat', type: 'button', onclick: () => aller('bouclier') }, icone('retour', 14), 'Bouclier');
  const tete = (titre, actions = []) => h('div', { class: 'headrow' },
    h('div', {}, vue !== 'ensemble' ? h('div', { class: 'fil' }, retour) : null, h('h1', { class: 'title', text: titre }), vue === 'ensemble' ? lede : null),
    h('div', { class: 'actions' }, ...actions));

  let corps;
  if (vue === 'ensemble') {
    corps = [
      tete('Bouclier', [
        admin ? h('button', { class: 'btn', type: 'button', onclick: () => ouvrir('reglages') }, icone('reglages', 15), 'Réglages') : null,
        admin ? h('button', { class: 'btn solid', type: 'button', onclick: () => bloquer() }, icone('bouclier', 15), 'Bloquer une adresse') : null]),
      figs, avis,
      h('div', { class: 'split' }, carteApercu('menaces', 'Menaces extérieures'), carteApercu('machines', 'Machines du réseau')),
      liens];
  } else if (vue === 'reglages') {
    corps = [tete(TITRES.reglages, [h('button', { class: 'btn', type: 'button', onclick: sur(async () => { const o = await api.post('/api/bouclier/listes/actualiser', {}); toast(o.faits.length ? `${o.faits.length} liste${o.faits.length > 1 ? 's' : ''} actualisée${o.faits.length > 1 ? 's' : ''}.` : 'Aucune liste téléchargée : voir les erreurs plus bas.', !o.faits.length); await peindre(); }) }, icone('liste', 15), 'Actualiser les listes')]),
      h('div', { class: 'grille' }, carteMode(), carteUnifi(), carteCloudflare(), carteSyslog(), carteListes(), carteBlanche(), carteExport(), carteSondes())];
  } else {
    const panneau = {
      menaces: () => carte('Toutes les menaces', h('span', { class: 'note', text: 'score effacé de moitié chaque heure' }), menaces),
      blocages: () => carte('Blocages', h('span', { class: 'note' }, h('span', { class: 'row' }, h('span', { text: 'Historique' }), interrupteur(false, 'Historique des blocages', v => { tousBlocages = v; peindre_(); }))), blocages),
      machines: () => carte('Machines du réseau', h('span', { class: 'note', text: 'isolement : réaction rapide' }), internes),
      alertes: () => carte('Alertes de l’IPS', h('span', { class: 'note', text: 'les plus récentes' }), alertes),
    }[vue]();
    corps = [tete(TITRES[vue], [admin && vue === 'menaces' ? h('button', { class: 'btn solid', type: 'button', onclick: () => bloquer() }, icone('bouclier', 15), 'Bloquer une adresse') : null]), panneau];
  }
  const page = h('div', { class: 'page' }, ...corps);
  peindre_();
  return page;

  // Réglages
  // Enregistrer puis repeindre la page entière : les cartes montrent l'état que le serveur a retenu.
  function enregistrer(corps, message) {
    return sur(async () => { await api.put('/api/reglages/bouclier', corps()); toast(message); await recharger(); });
  }

  function carteMode() {
    const r = reglages;
    const mode = h('select', { class: 'field', 'aria-label': 'Mode' }, Object.entries(MODES).map(([v, t]) => h('option', { value: v, text: t, selected: v === r.mode })));
    const nombre = (v, min, max, libelle) => h('input', { class: 'field', type: 'number', min, max, value: v, 'aria-label': libelle });
    const seuil = nombre(r.seuil, 30, 1000, 'Seuil extérieur');
    const seuilInterne = nombre(r.seuilInterne, 30, 1000, 'Seuil interne');
    const demi = nombre(r.demiVieMinutes, 5, 1440, 'Demi-vie');
    const ports = nombre(r.balayagePorts, 5, 1000, 'Ports');
    const cibles = nombre(r.balayageCibles, 3, 1000, 'Machines');
    const brute = nombre(r.forceBrute, 3, 1000, 'Tentatives');
    const parHeure = nombre(r.autoParHeure, 1, 2000, 'Blocages par heure');
    const max = nombre(r.maxUnifi, 10, 10000, 'Adresses sur la passerelle');
    const durees = h('input', { class: 'field mono', value: r.dureesMinutes.join(', '), 'aria-label': 'Durées' });
    const tSources = nombre(r.tempeteSources, 5, 100000, 'Sources'), tLignes = nombre(r.tempeteLignes, 50, 1000000, 'Lignes'), tBlocages = nombre(r.tempeteBlocages, 0, 500, 'Blocages'), tMinutes = nombre(r.tempeteMinutes, 1, 1440, 'Minutes');
    const deux = (a, b) => h('div', { class: 'deux' }, a, b);
    const corps = () => ({
      mode: mode.value, seuil: Number(seuil.value), seuilInterne: Number(seuilInterne.value), demiVieMinutes: Number(demi.value),
      balayagePorts: Number(ports.value), balayageCibles: Number(cibles.value), forceBrute: Number(brute.value),
      autoParHeure: Number(parHeure.value), maxUnifi: Number(max.value), dureesMinutes: lignes(durees.value).map(Number),
      tempeteSources: Number(tSources.value), tempeteLignes: Number(tLignes.value), tempeteBlocages: Number(tBlocages.value), tempeteMinutes: Number(tMinutes.value),
    });
    const sauver = enregistrer(corps, 'Bouclier enregistré.');
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Mode et seuils' }), h('span', { class: 'note', text: r.mode })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Chaque observation ajoute des points à l’adresse qui la porte : alerte d’IPS de gravité 1 = 100, 2 = 40, 3 = 10 ; balayage ou force brute = 60 ; présence sur une liste de menaces = son poids. Au seuil, l’adresse extérieure est bloquée ; une machine du réseau est signalée (et isolée seulement par la réaction rapide, si elle est allumée).' }),
      h('label', { class: 'lbl mt9', text: 'Mode' }), mode,
      h('label', { class: 'lbl mt9', text: 'Seuils : extérieur · machine du réseau' }), deux(seuil, seuilInterne),
      h('label', { class: 'lbl mt9', text: 'Demi-vie du score (minutes)' }), demi,
      h('label', { class: 'lbl mt9', text: 'En dix minutes : ports d’une cible · machines visées' }), deux(ports, cibles),
      h('label', { class: 'lbl mt9', text: 'Force brute : tentatives sur un port d’authentification en dix minutes' }), brute,
      h('label', { class: 'lbl mt9', text: 'Blocages automatiques par heure · adresses tenues par la passerelle' }), deux(parHeure, max),
      h('label', { class: 'lbl mt9', text: 'Durées des blocages successifs (minutes)' }), durees,
      h('label', { class: 'lbl mt12', text: 'Tempête (déni de service) : sources distinctes sur un même port · lignes entrantes, en une minute' }), deux(tSources, tLignes),
      h('label', { class: 'lbl mt9', text: 'En tempête : adresses les plus bruyantes bloquées d’emblée (hors plafond) · minutes de mode « Under Attack » Cloudflare' }), deux(tBlocages, tMinutes),
      h('p', { class: 'hint', text: 'Au-delà de la frontière, un déni de service volumétrique sature la ligne avant la passerelle : il se traite en amont (Cloudflare pour ce qui passe par le tunnel, sinon le fournisseur d’accès). VIGIE le dit, bloque ce qu’il peut, et bascule Cloudflare si tu l’y autorises.' }),
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: async () => {
        if (mode.value === 'actif' && r.mode !== 'actif' && !(await confirmer('Laisser VIGIE bloquer seul ?', 'Une adresse extérieure qui dépasse le seuil sera coupée à la frontière sans attendre personne. Jamais une adresse du réseau local, jamais la liste blanche ; chaque blocage se lève en un clic.', { danger: true, oui: 'Passer en actif' }))) return;
        await sauver();
      } }, 'Enregistrer'))));
  }

  function carteUnifi() {
    const r = reglages;
    const u = etat.unifi;
    const p = etat.passerelle || {};
    const parMml = u.relie && !u.directe;
    const hote = h('input', { class: 'field mono', value: r.unifiHote, placeholder: 'adresse IP de la passerelle UniFi', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Adresse de la passerelle' });
    const port = h('input', { class: 'field', type: 'number', min: 1, max: 65535, value: r.unifiPort || 443, 'aria-label': 'Port' });
    const cle = h('input', { class: 'field mono', type: 'password', placeholder: r.cleUnifi ? 'clé enregistrée — en coller une autre pour la remplacer' : 'clé d’API UniFi', autocomplete: 'off', 'aria-label': 'Clé d’API' });
    const fp = h('p', { class: 'mono hint mt0 coupe', text: r.unifiFp ? `Certificat épinglé : ${r.unifiFp}` : 'Aucun certificat épinglé.' });
    let empreinte = r.unifiFp || '';
    const lire = sur(async () => {
      const o = await api.post('/api/bouclier/unifi/sonde', { hote: hote.value.trim(), port: Number(port.value) || 443 });
      const ok = await confirmer('Est-ce bien ta passerelle ?', `Certificat présenté par ${hote.value.trim()} : « ${o.sujet || 'sans nom'} », valable jusqu’au ${o.expire || '?'} — empreinte ${o.fp}. S’il est confirmé, VIGIE n’enverra sa clé qu’à une machine qui présente exactement ce certificat.`, { oui: 'C’est elle' });
      if (!ok) return;
      empreinte = o.fp;
      fp.textContent = `Certificat à épingler : ${o.fp}`;
      toast('Certificat retenu : colle la clé d’API puis enregistre.');
    });
    const etatTexte = !u.relie ? 'non reliée' : u.ok === false ? 'erreur' : u.ok ? (parMml ? 'par MapMyLAN' : 'synchronisée') : 'reliée';
    const regles = u.regles && !u.regles.erreur ? u.regles : null;
    const nom4 = u.listes?.[4]?.nom || (parMml ? 'VIGIE bloquees IPv4' : 'VIGIE · bloquées IPv4');
    const nom6 = u.listes?.[6]?.nom || (parMml ? 'VIGIE bloquees IPv6' : 'VIGIE · bloquées IPv6');
    const voie = parMml
      ? h('p', { class: 'hint mt0', text: `Reliée automatiquement par MapMyLAN : ${p.nom || 'routeur principal'} (${p.hote}). Rien à régler : les identifiants du routeur restent dans MapMyLAN, VIGIE y tient les groupes « ${nom4} » et « ${nom6} », et rien d’autre.` })
      : u.directe ? h('p', { class: 'hint mt0', text: 'Reliée directement par l’API d’intégration d’UniFi Network (clé posée ici). Elle passe avant MapMyLAN.' })
        : p.reliee ? h('p', { class: 'hint mt0', text: `Le routeur relié à MapMyLAN (${p.libelle || p.nom}) ne sait pas encore tenir une liste d’adresses : relie une passerelle UniFi directement ci-dessous.` })
          : h('p', { class: 'hint mt0', text: `Aucune passerelle. Le plus simple : relier le routeur dans MapMyLAN (Équipement réseau) — VIGIE s’en sert alors seule, sans rien régler ici.${p.ancien ? ' (Ton MapMyLAN est trop ancien pour ça : mets-le à jour depuis le Hub.)' : ''}` });
    const etatLigne = u.relie ? h('div', { class: 'etat-unifi' },
      h('small', { text: u.ok ? `${u.envoyees ?? 0} adresse${u.envoyees > 1 ? 's' : ''} envoyée${u.envoyees > 1 ? 's' : ''} · ${quand(u.synchro)}` : u.erreur || 'pas encore synchronisée' }),
      regles ? h('small', { text: `Règles qui citent les listes : entrée ${regles.entrant ? 'oui' : 'NON'} · sortie ${regles.sortant ? 'oui' : 'NON'}${regles.regles?.length ? ` (${regles.regles.map(x => x.nom).join(', ')})` : ''}` }) : null) : null;
    const directe = h('details', { class: 'mt12', ...(u.directe ? { open: true } : {}) }, h('summary', { text: parMml ? 'Relier directement par une clé d’API (facultatif)' : 'Relier directement par une clé d’API UniFi' }),
      h('label', { class: 'lbl mt9', text: '1. Adresse et port de la passerelle' }), h('div', { class: 'deux' }, hote, port),
      h('div', { class: 'actions mt9' }, h('button', { class: 'btn sm', type: 'button', onclick: lire }, 'Lire son certificat')), fp,
      h('label', { class: 'lbl mt9', text: '2. Clé d’API — UniFi Network → Paramètres → Control Plane → Integrations → Create API Key' }), cle,
      u.directe ? h('div', { class: 'actions mt12' }, h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => {
        if (!(await confirmer('Délier la passerelle ?', 'La clé est effacée de VIGIE. Les listes restent sur la passerelle telles quelles. Si MapMyLAN pilote le routeur, VIGIE repasse par lui.', { danger: true, oui: 'Délier' }))) return;
        await api.put('/api/bouclier/unifi', { retirer: true }); toast('Passerelle déliée.'); await recharger();
      }) }, 'Délier')) : null,
      h('div', { class: 'actions mt9' }, h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
        if (!empreinte) throw new Error('Lis d’abord le certificat de la passerelle.');
        etat = await api.put('/api/bouclier/unifi', { hote: hote.value.trim(), port: Number(port.value) || 443, fp: empreinte, ...(cle.value.trim() ? { cle: cle.value.trim() } : {}) });
        toast(etat.unifi.ok ? 'Passerelle reliée : listes créées.' : `Enregistrée, mais : ${etat.unifi.erreur || 'pas de réponse'}`, etat.unifi.ok === false);
        await recharger();
      }) }, 'Enregistrer')));
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Passerelle' }), h('span', { class: `note ${u.ok === false ? 'erreur' : ''}`, text: etatTexte })), h('div', { class: 'cardbody' },
      voie, etatLigne,
      u.relie ? h('div', { class: 'actions mt9' }, h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { const o = await api.post('/api/bouclier/unifi/synchroniser', {}); toast(o.ok ? 'Passerelle synchronisée.' : o.erreur, !o.ok); await peindre(); }) }, 'Synchroniser')) : null,
      directe,
      h('details', { class: 'mt12', ...(regles && (!regles.entrant || !regles.sortant) ? { open: true } : {}) }, h('summary', { text: 'Les règles à poser une fois dans UniFi (sans elles, les listes ne bloquent rien)' }),
        h('ol', { class: 'etapes' },
          h('li', { text: 'Paramètres → Policy Engine (ou Firewall & Security selon la version) → Create Policy.' }),
          h('li', { text: `« VIGIE entrée » : action Block, zone source External, source = le groupe d’adresses « ${nom4} », destination : toutes les zones internes. Journalisation (Syslog) cochée.` }),
          h('li', { text: '« VIGIE sortie » : action Block, zones sources internes, destination = le même groupe, zone External. Une machine infectée ne joint plus son serveur de commande.' }),
          h('li', { text: `Les deux mêmes pour « ${nom6} » si l’IPv6 est actif.` }),
          h('li', { text: 'Placer ces règles avant les règles d’autorisation, puis « Synchroniser » ici : VIGIE vérifie qu’elles existent.' })))));
  }

  function carteCloudflare() {
    const r = reglages;
    const c = etat.cloudflare || {};
    const jeton = h('input', { class: 'field mono', type: 'password', placeholder: r.cloudflareJeton ? 'jeton enregistré — en coller un autre pour le remplacer' : 'jeton d’API Cloudflare', autocomplete: 'off', 'aria-label': 'Jeton Cloudflare' });
    const zonesBoite = h('div', { class: 'mt9' });
    let zonesLues = null;
    const choisies = () => [...zonesBoite.querySelectorAll('input:checked')].map(x => ({ id: x.value, nom: x.dataset.nom }));
    const peindreZones = (zones, cochees) => zonesBoite.replaceChildren(...(zones.length ? zones.map(z => h('label', { class: 'check' }, h('input', { type: 'checkbox', value: z.id, 'data-nom': z.nom, checked: cochees.some(x => x.id === z.id) }), ` ${z.nom}${z.offre ? ` (${z.offre})` : ''}`)) : [h('p', { class: 'hint', text: 'Aucune zone lisible avec ce jeton.' })]));
    if ((r.cloudflareZones || []).length) peindreZones(r.cloudflareZones, r.cloudflareZones);
    const sonder = sur(async () => {
      const o = await api.post('/api/bouclier/cloudflare/sonde', jeton.value.trim() ? { jeton: jeton.value.trim() } : {});
      zonesLues = o.zones; peindreZones(o.zones, r.cloudflareZones || []);
      toast(`Jeton valable : ${o.zones.length} zone${o.zones.length > 1 ? 's' : ''}. Coche celles à protéger, puis enregistre.`);
    });
    const modeAuto = interrupteur(!!r.cloudflareModeAttaque, 'Mode Under Attack automatique en tempête', v => sur(async () => { await api.put('/api/reglages/bouclier', { cloudflareModeAttaque: v }); toast(v ? 'En tempête, Cloudflare passera en mode Under Attack.' : 'Plus de bascule automatique.'); })());
    const a = c.attaque;
    const etatTexte = !c.relie ? 'non relié' : c.ok === false ? 'erreur' : c.ok ? 'synchronisé' : 'relié';
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Cloudflare, en amont' }), h('span', { class: `note ${c.ok === false ? 'erreur' : ''}`, text: etatTexte })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Les adresses bloquées vont aussi dans une liste de ton compte Cloudflare (« vigie_bloquees »), qu’une règle du pare-feu applicatif refuse sur chaque zone choisie : l’attaquant est coupé avant le tunnel. En tempête, VIGIE peut passer les zones en mode « Under Attack » (défi à chaque visiteur) le temps réglé.' }),
      c.relie ? h('div', { class: 'etat-unifi' },
        h('small', { text: c.ok ? `${c.envoyees ?? 0} adresse${c.envoyees > 1 ? 's' : ''} dans la liste · ${quand(c.synchro)}` : c.erreur || 'pas encore synchronisé' }),
        (c.zones || []).length ? h('small', { text: `Zones : ${c.zones.map(z => `${z.nom}${z.regle ? '' : ' (règle manquante' + (z.erreur ? ' : ' + z.erreur : '') + ')'}`).join(', ')}` }) : h('small', { class: 'erreur-texte', text: 'Aucune zone choisie : la liste existe mais rien ne la refuse.' }),
        a ? h('small', { class: 'erreur-texte', text: `Mode Under Attack en cours (${a.motif}) jusqu’à ${quand(a.jusqua)}` }) : null) : null,
      h('label', { class: 'lbl mt9', text: 'Jeton d’API — Cloudflare → Mon profil → Jetons d’API → Créer : Compte → Listes de filtres : Modifier · Zone → Zone : Lire · Zone → Pare-feu WAF : Modifier · Zone → Paramètres de zone : Modifier' }), jeton,
      h('div', { class: 'actions mt9' }, h('button', { class: 'btn sm', type: 'button', onclick: sonder }, 'Lire les zones')),
      h('label', { class: 'lbl mt9', text: 'Zones protégées' }), zonesBoite,
      h('div', { class: 'reglage-ligne' }, h('div', {}, h('strong', { text: 'Mode « Under Attack » automatique' }), h('small', { text: 'En tempête, pour la durée réglée dans « Mode et seuils » ; l’ancien niveau de sécurité revient ensuite.' })), c.relie ? modeAuto : h('span', { class: 'note', text: 'relier d’abord' })),
      h('div', { class: 'actions mt12' },
        h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
          const corps = { ...(jeton.value.trim() ? { jeton: jeton.value.trim() } : {}), ...(zonesLues || (r.cloudflareZones || []).length ? { zones: choisies() } : {}) };
          if (!corps.jeton && !r.cloudflareJeton) throw new Error('Colle d’abord un jeton.');
          await api.put('/api/bouclier/cloudflare', corps); toast('Cloudflare enregistré et synchronisé.'); await recharger();
        }) }, 'Enregistrer'),
        c.relie ? h('button', { class: 'btn', type: 'button', onclick: sur(async () => { await api.post('/api/bouclier/cloudflare/synchroniser', {}); toast('Liste resynchronisée.'); await recharger(); }) }, 'Resynchroniser') : null,
        c.relie && (c.zones || []).length ? h('button', { class: `btn ${a ? '' : 'danger'}`, type: 'button', onclick: sur(async () => {
          if (!a && !(await confirmer('Passer en mode Under Attack ?', 'Chaque visiteur des zones choisies verra un défi de 5 secondes pendant 15 minutes. À réserver à une attaque en cours.', { danger: true, oui: 'Passer' }))) return;
          await api.post('/api/bouclier/cloudflare/attaque', { actif: !a, minutes: 15 }); toast(a ? 'Mode Under Attack levé.' : 'Mode Under Attack posé pour 15 minutes.'); await recharger();
        }) }, a ? 'Lever le mode Under Attack' : 'Under Attack 15 min') : null,
        c.relie ? h('button', { class: 'btn sm flat', type: 'button', onclick: sur(async () => {
          if (!(await confirmer('Délier Cloudflare ?', 'Le jeton est effacé de VIGIE ; la liste et la règle restent dans Cloudflare telles quelles.', { danger: true, oui: 'Délier' }))) return;
          await api.put('/api/bouclier/cloudflare', { retirer: true }); toast('Cloudflare délié.'); await recharger();
        }) }, 'Délier') : null)));
  }

  function carteSyslog() {
    const s = etat.syslog;
    const emetteurs = Object.entries(s.parEmetteur || {});
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Journaux de la passerelle' }), h('span', { class: `note ${!s.lues ? 'erreur' : ''}`, text: s.lues ? `dernier ${depuis(s.derniere)}` : 'rien reçu' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Les journaux donnent tout : alertes de l’IPS (le Suricata intégré à la passerelle UniFi), pot de miel, refus du pare-feu. Si MapMyLAN pilote le routeur, les alertes de l’IPS arrivent déjà sans eux.' }),
      h('dl', { class: 'preuve' },
        h('dt', { text: 'Serveur' }), h('dd', { text: 'adresse IP locale de la machine de VIGIE' }),
        h('dt', { text: 'Port' }), h('dd', { text: `${s.port || '—'} (UDP ou TCP)` }),
        ...(etat.passerelle?.ips ? [h('dt', { text: 'Relève IPS' }), h('dd', { text: etat.passerelle.releve.erreur ? `erreur : ${etat.passerelle.releve.erreur}` : etat.passerelle.releve.active ? `par MapMyLAN · ${etat.passerelle.releve.lues} alertes · ${depuis(etat.passerelle.releve.derniere)}` : 'en pause : les alertes arrivent déjà par syslog' })] : []),
        h('dt', { text: 'Reçues · lues' }), h('dd', { text: `${s.recues.toLocaleString('fr-FR')} · ${s.lues.toLocaleString('fr-FR')}` }),
        h('dt', { text: 'Refusées' }), h('dd', { text: `${s.refusees} (émetteur non déclaré)${s.dernierRefus ? ` · dernier : ${s.dernierRefus}` : ''}${s.debordees ? ` · ${s.debordees} au-delà de 3 000/s` : ''}` }),
        ...emetteurs.flatMap(([ip, t]) => [h('dt', { text: 'Émetteur' }), h('dd', {}, `${ip} · ${depuis(t)}`,
          // Un émetteur vu mais pas déclaré : un clic le déclare, et la riposte devient automatique.
          admin && reglages && !(reglages.emetteurs || []).includes(ip) ? h('button', { class: 'btn sm mt9', type: 'button', onclick: sur(async () => {
            if (!(await confirmer(`Déclarer ${ip} ?`, `VIGIE ne lira plus que les journaux venus de ${ip}${(reglages.emetteurs || []).length ? ' et des émetteurs déjà déclarés' : ''}, et pourra bloquer seul ce qu’ils montrent.`, { oui: 'Déclarer' }))) return;
            await api.put('/api/reglages/bouclier', { emetteurs: [...(reglages.emetteurs || []), ip] });
            toast(`${ip} déclaré.`);
            await recharger();
          }) }, 'Déclarer') : null)])),
      h('ol', { class: 'etapes' },
        h('li', { text: 'UniFi Network → Paramètres → Control Plane → Integrations → Activity Logging (Syslog) : « SIEM Server », l’adresse et le port ci-dessus. Catégories Security : Firewall, Honeypot, Intrusion Prevention (format CEF).' }),
        h('li', { text: 'Paramètres → CyberSecure → Traffic Logging : « SIEM Server », même adresse et même port (lignes du pare-feu : balayages, force brute).' }),
        h('li', { text: 'CyberSecure → Intrusion Prevention : mode « Prévention » (IPS) sur tous les réseaux, catégories au maximum. Le pot de miel (Honeypot) sur les réseaux internes : une machine qui le touche est presque toujours compromise.' }),
        h('li', { text: 'Seuls les émetteurs déclarés (carte « Liste blanche et émetteurs ») sont lus ; sans liste, toute adresse privée l’est.' }))));
  }

  function carteListes() {
    const choix = Object.fromEntries(etat.listes.map(l => [l.id, l.active]));
    const toutes = h('div', {}, etat.listes.map(l => h('div', { class: 'reglage-ligne' },
      h('div', {}, h('strong', { text: `${l.nom}${l.propre ? ' (ajoutée)' : ''}` }),
        h('small', { text: `${l.sujet} · poids ${l.poids}` }),
        h('small', { class: l.erreur ? 'erreur-texte' : '', text: l.erreur ? `erreur : ${l.erreur}` : l.entrees ? `${l.entrees.toLocaleString('fr-FR')} ${l.type === 'ip' ? 'plage' : 'domaine'}${l.entrees > 1 ? 's' : ''} · ${quand(l.maj)}` : 'pas encore téléchargée' })),
      interrupteur(l.active, l.nom, v => { choix[l.id] = v; }))));
    const nom = h('input', { class: 'field', maxlength: 60, placeholder: 'nom', 'aria-label': 'Nom de la liste' });
    const type = h('select', { class: 'field', 'aria-label': 'Type' }, h('option', { value: 'ip', text: 'adresses IP' }), h('option', { value: 'domaine', text: 'domaines' }));
    const url = h('input', { class: 'field mono', placeholder: 'https://…', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Adresse de la liste' });
    const poids = h('input', { class: 'field', type: 'number', min: 5, max: 100, value: 50, 'aria-label': 'Poids' });
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Listes de menaces' }), h('span', { class: 'note', text: `toutes les ${reglages.listesHeures} h` })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Réputation partagée (abuse.ch, Spamhaus, Emerging Threats…). Une liste ne bloque rien seule : elle pèse dans le score d’une adresse que VIGIE voit vraiment passer — on bloque ce qui frappe, pas un million d’adresses par précaution.' }),
      toutes,
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: enregistrer(() => ({ listes: choix }), 'Listes enregistrées : téléchargement lancé.') }, 'Enregistrer')),
      h('details', { class: 'mt12' }, h('summary', { text: 'Ajouter une liste (texte, une entrée par ligne, en HTTPS)' }),
        h('div', { class: 'deux mt9' }, nom, type), h('div', { class: 'mt9' }, url), h('label', { class: 'lbl mt9', text: 'Poids (100 = blocage dès qu’elle est vue)' }), poids,
        h('div', { class: 'actions mt9' },
          (reglages.listesPropres || []).length ? h('button', { class: 'btn sm', type: 'button', onclick: enregistrer(() => ({ listesPropres: [] }), 'Listes ajoutées retirées.') }, 'Retirer les listes ajoutées') : null,
          h('button', { class: 'btn sm', type: 'button', onclick: enregistrer(() => ({ listesPropres: [...(reglages.listesPropres || []), { nom: nom.value.trim(), type: type.value, url: url.value.trim(), poids: Number(poids.value) }] }), 'Liste ajoutée.') }, 'Ajouter')))));
  }

  function carteBlanche() {
    const blanche = h('textarea', { class: 'field mono', rows: 4, placeholder: '203.0.113.0/24', spellcheck: 'false', 'aria-label': 'Liste blanche' });
    blanche.value = (reglages.listeBlanche || []).join('\n');
    const emetteurs = h('textarea', { class: 'field mono', rows: 2, placeholder: 'adresse de la passerelle UniFi', spellcheck: 'false', 'aria-label': 'Émetteurs' });
    emetteurs.value = (reglages.emetteurs || []).join('\n');
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Liste blanche et émetteurs' })), h('div', { class: 'cardbody' },
      h('label', { class: 'lbl', text: 'Jamais bloquées (une adresse ou plage par ligne) — tes IP publiques, ton VPN, tes services en ligne' }), blanche,
      h('p', { class: 'hint', text: `Toujours protégées, sans rien écrire : le réseau local et les adresses réservées, ${reglages.listeBlancheDefaut.length} plages de résolveurs DNS publics et de Cloudflare (le tunnel du Hub passe par là).` }),
      h('label', { class: 'lbl mt9', text: 'Émetteurs de journaux acceptés — vide : toute adresse privée' }), emetteurs,
      h('p', { class: 'hint', text: 'Un journal se falsifie : n’écouter que la passerelle évite qu’une machine du réseau fasse bloquer une adresse en inventant des alertes.' }),
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: enregistrer(() => ({ listeBlanche: lignes(blanche.value), emetteurs: lignes(emetteurs.value) }), 'Enregistré.') }, 'Enregistrer'))));
  }

  function carteExport() {
    const sortie = h('div', {});
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Liste pour un autre pare-feu' }), h('span', { class: 'note', text: reglages.jetonListe ? 'jeton posé' : 'aucun jeton' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Les adresses bloquées en texte, une par ligne, pour un pare-feu qui lit une URL (pfSense ou OPNsense en alias « URL Table », MikroTik…). Le jeton est dans l’adresse : ces pare-feu n’envoient pas d’en-tête.' }),
      sortie,
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn', type: 'button', onclick: sur(async () => {
        if (reglages.jetonListe && !(await confirmer('Nouveau jeton ?', 'L’ancienne adresse cesse de fonctionner aussitôt.', { oui: 'Remplacer' }))) return;
        const o = await api.post('/api/bouclier/jeton-liste', {});
        reglages.jetonListe = true;
        sortie.replaceChildren(h('p', { class: 'hint', text: 'Montrée une seule fois :' }), h('p', { class: 'mono coupe', text: location.origin + o.chemin }));
      }) }, reglages.jetonListe ? 'Nouveau jeton' : 'Créer l’adresse'))));
  }

  function carteSondes() {
    const nom = h('input', { class: 'field mono', maxlength: 40, placeholder: 'nom-de-la-sonde', autocomplete: 'off', 'aria-label': 'Nom' });
    const sortie = h('div', {});
    const liste = etat.sondes;
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Sondes (facultatif)' }), h('span', { class: 'note', text: liste.length ? `${liste.length}` : 'aucune' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Une sonde Suricata placée ailleurs sur le réseau peut envoyer son EVE JSON à POST /api/sonde/eve, avec son propre jeton. Sans sonde déclarée, cette entrée refuse tout.' }),
      liste.map(s => h('div', { class: 'reglage-ligne' }, h('div', {}, h('strong', { class: 'ip', text: s.nom }), h('small', { text: `${s.lues.toLocaleString('fr-FR')} événements · dernier ${depuis(s.derniere)}` })),
        h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { if (!(await confirmer(`Retirer la sonde ${s.nom} ?`, 'Son jeton cesse de fonctionner aussitôt.', { danger: true, oui: 'Retirer' }))) return; await api.post('/api/bouclier/sondes/retirer', { nom: s.nom }); toast('Sonde retirée.'); await recharger(); }) }, 'Retirer'))),
      h('div', { class: 'deux mt9' }, nom, h('button', { class: 'btn', type: 'button', onclick: sur(async () => {
        const o = await api.post('/api/bouclier/sondes', { nom: nom.value.trim() });
        sortie.replaceChildren(h('p', { class: 'hint', text: `Jeton de ${o.nom}, montré une seule fois :` }), h('p', { class: 'mono coupe', text: o.jeton }));
        nom.value = '';
      }) }, 'Créer un jeton')), sortie));
  }
}
