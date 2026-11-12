// Une VIGIE de démonstration contre de faux voisins (test/faux.js) : deux
// audits (le second relu par l'IA locale), des événements de veille, des
// actions — et la porte du socle à ouvrir.
//   node outils/vitrine.mjs 8197
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { demarrer } from '../src/main.js';
import { fauxServices, fausseSonde, JETON_DOCKER } from '../test/faux.js';
import { lireLigne } from '../src/bouclier/journaux.js';
import { FLUX } from '../src/bouclier/menaces.js';
import { TablePays, lireDelegue } from '../src/bouclier/geo.js';

const port = Number(process.argv[2] || 8197);
const dossier = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-vitrine-'));
const faux = fauxServices();
await new Promise(r => faux.serveur.listen(0, '127.0.0.1', r));
const ext = `http://127.0.0.1:${faux.serveur.address().port}`;
const jeton = 'jeton-installation-de-la-vitrine-vigie';
// Listes de menaces de démonstration : rien ne part vers Internet.
const fauxFlux = url => {
  if (url === FLUX.feodo.url) return new Response('185.220.101.7\n45.137.21.9\n');
  if (url === FLUX['spamhaus-drop'].url) return new Response('{"cidr":"45.155.205.0/24"}\n{"cidr":"91.240.118.0/24"}\n');
  if (url === FLUX['blocklist-de'].url) return new Response('80.94.95.0\n141.98.11.4\n');
  if (url === FLUX.urlhaus.url) return new Response('127.0.0.1 cdn-maj.exemple-malveillant.net\n');
  return new Response('', { status: 503 });
};
const vigie = await demarrer({
  DATA_DIR: path.join(dossier, 'data'), PORT: String(port), HOTE: '127.0.0.1', SOCLE_JETON_INSTALLATION: jeton, VIGIE_HUB_TOKEN: 'jeton-du-hub-de-la-vitrine-0123456789',
  MAPMYLAN_URL: ext + '/mml', MAPMYLAN_JETON: faux.jetons.mml, NEXARC_URL: ext + '/nxr', NEXARC_JETON: faux.jetons.nxr, DOCKER_CONTROL_URL: ext + '/dck',
  IA_LOCALE_URL: ext + '/ollama', IA_LOCALE_MODELE: 'qwen3:8b', SYNAPSE_URL: ext + '/syn', SYNAPSE_JETON: faux.jetons.syn,
  VIGIE_SYSLOG_PORT: '0', VIGIE_SYSLOG_PORT_HOTE: '5514',
  ...(process.env.SOCLE_THEME ? { SOCLE_THEME: process.env.SOCLE_THEME } : {}),
}, { log: { info() {}, warn() {}, error() {} }, sonde: fausseSonde, fetchMenaces: async url => fauxFlux(url) });
const fin = async x => { await vigie.moteur.enCours?.travail; return x; };
vigie.magasin.poserSecret('docker', 'jeton', JETON_DOCKER);
// Un premier audit plus propre, pour la courbe : la caméra n'avait pas encore Telnet.
const camera = faux.etat.appareils.find(a => a.id === 'camera');
const ports = camera.ports; camera.ports = ports.filter(p => p.port !== 23);
await fin(vigie.moteur.lancer({ declencheur: 'quotidien', ia: false }));
camera.ports = ports;
await vigie.moteur.passe();
faux.etat.appareils.push({ id: 'neuf', ip: '192.0.2.77', mac: 'AA:00:00:00:00:77', hostname: 'imprimante-etage-2-salle-de-reunion-principale', type: 'printer', vlan: 1, status: 'online', dangerScore: 10, whitelisted: false, ports: [{ port: 9100, state: 'open', service: 'jetdirect' }], cves: [] });
await vigie.moteur.passe();
vigie.magasin.poserReglage('ia', { mode: 'locale' });
await fin(vigie.moteur.lancer({ declencheur: 'manuel', auteur: 'ana' }));
await vigie.moteur.executer({ type: 'deep-scan', appareil: 'camera', auteur: 'ana' });
faux.etat.actionPrend = false;
await vigie.moteur.executer({ type: 'quarantine', appareil: 'camera', motif: 'Telnet ouvert', auteur: 'ana' });
faux.etat.actionPrend = true;
await vigie.moteur.executer({ type: 'quarantine', appareil: 'intrus', motif: 'Signe d’intrusion', auteur: 'vigie', automatique: true });
// Le bouclier : journaux d'une passerelle UniFi de démonstration, une passerelle qui répond.
const b = vigie.bouclier;
await b.menaces.actualiser({ forcer: true });
const passerelle = l => { const o = lireLigne(l, 'syslog:192.0.2.1'); if (o) { b.recepteur.stats.recues++; b.recepteur.stats.lues++; b.recepteur.stats.derniere = Date.now(); b.recepteur.stats.parEmetteur['192.0.2.1'] = Date.now(); b.observer(o); } };
const cef = (nom, ext) => `<132>Oct 13 10:00:00 passerelle CEF:0|Ubiquiti|UniFi Network|9.4.19|544|${nom}|7|${ext}`;
passerelle(cef('Threat Detected and Blocked', 'src=45.155.205.10 spt=51111 dst=10.9.10.20 dpt=22 proto=TCP UNIFIcategory=Security UNIFIsubCategory=Intrusion Prevention UNIFIipsSignature=ET SCAN Potential SSH Scan OUTBOUND UNIFIipsSignatureId=2003068 UNIFIrisk=high'));
passerelle(cef('Threat Detected and Blocked', 'src=193.32.162.8 spt=40111 dst=10.9.10.30 dpt=445 proto=TCP UNIFIcategory=Security UNIFIipsSignature=ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 UNIFIipsSignatureId=2024218 UNIFIrisk=medium'));
passerelle(cef('Threat Detected', 'src=193.32.162.8 spt=40112 dst=10.9.10.30 dpt=3389 proto=TCP UNIFIcategory=Security UNIFIipsSignature=ET SCAN MS Terminal Server Traffic on Non-standard Port UNIFIipsSignatureId=2023753 UNIFIrisk=low'));
passerelle(cef('Honeypot Triggered', 'UNIFIcategory=Security UNIFIsubCategory=Honeypot src=10.9.10.77 dst=10.9.10.2 dpt=23 msg=Honeypot accessed'));
for (let p = 1000; p < 1016; p++) passerelle(`<4>Oct 13 10:00:01 passerelle kernel: [WAN_IN-D-2147483647] IN=eth8 OUT= SRC=141.98.11.4 DST=203.0.113.5 LEN=60 PROTO=TCP SPT=40000 DPT=${p} SYN`);
for (let i = 0; i < 6; i++) passerelle(`<4>Oct 13 10:00:02 passerelle kernel: [WAN_IN-D-2147483647] IN=eth8 OUT= SRC=80.94.95.12 DST=203.0.113.5 LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN`);
b.correlateur.observer({ type: 'flux', src: '10.9.10.50', dst: '185.220.101.7', dport: 443, capteur: 'syslog:192.0.2.1' });
await new Promise(r => setTimeout(r, 50));
await b.riposte.bloquer({ ip: '2a01:4f8:c0c:1234::7', minutes: 1440, motif: 'balayage IPv6 vu dans les journaux du NAS', raisons: ['balayage IPv6 vu dans les journaux du NAS'], auteur: 'ana' });
const ancien = await b.riposte.bloquer({ ip: '103.145.13.20', minutes: 60, motif: 'force brute : 24 tentatives sur le port 22', raisons: ['force brute : 24 tentatives sur le port 22'], auteur: 'vigie', automatique: true });
await b.riposte.lever(ancien.id, 'ana');
// La passerelle que MapMyLAN pilote : reliée seule, sans clé dans VIGIE.
// VITRINE_SANS_EMETTEUR=1 : la passerelle reste non déclarée (l'accueil propose de la déclarer).
if (process.env.VITRINE_SANS_EMETTEUR !== '1') vigie.magasin.poserReglage('bouclier', { emetteurs: ['192.0.2.1'] });
b.passerelle = { reliee: true, nom: 'Passerelle', hote: '192.0.2.1', libelle: 'Ubiquiti · UniFi', bouclier: true, ips: true, lu: Date.now() };
b.lirePasserelle = async () => b.passerelle;
b.releverIps = async () => 0;
b.releve = { ...b.releve, derniere: Date.now(), lues: 4 };
b.riposte.passerelleAuto = () => ({ forme: 'mapmylan', nom: 'Passerelle', synchroniser: async l => ({ 4: { id: 'g4', nom: 'VIGIE bloquees IPv4', n: l.length }, 6: { id: 'g6', nom: 'VIGIE bloquees IPv6', n: 0 } }), regles: async () => ({ entrant: true, sortant: true, regles: [{ nom: 'VIGIE entree', actif: true }, { nom: 'VIGIE sortie', actif: true }] }) });
await b.riposte.synchroniser({ forcer: true });
// La carte : des registres d'Internet de démonstration (quelques blocs, rien
// téléchargé) et vingt-quatre heures d'attaques tirées au sort, toujours les mêmes.
const BLOCS = [['218.92.0.0', 65536, 'CN'], ['61.177.172.0', 256, 'CN'], ['45.155.205.0', 256, 'RU'], ['91.240.118.0', 256, 'RU'], ['194.26.29.0', 256, 'RU'],
  ['193.32.162.0', 256, 'NL'], ['141.98.11.0', 256, 'LT'], ['80.94.95.0', 256, 'RO'], ['185.220.101.0', 256, 'DE'], ['103.145.13.0', 256, 'IN'],
  ['179.43.180.0', 256, 'CH'], ['170.64.230.0', 256, 'AU'], ['20.163.0.0', 65536, 'US'], ['87.120.84.0', 256, 'BG'], ['177.54.144.0', 4096, 'BR'],
  ['121.170.0.0', 65536, 'KR'], ['128.199.0.0', 65536, 'SG'], ['183.81.169.0', 256, 'VN'], ['41.216.186.0', 256, 'ZA'], ['190.12.0.0', 65536, 'AR']];
b.geo.table = new TablePays(lireDelegue(BLOCS.map(([d, n, cc]) => `ripencc|${cc}|ipv4|${d}|${n}|20100101|allocated|demo`).join('\n') + '\nripencc|DE|ipv6|2a01:4f8::|32|20100101|allocated|demo'));
b.geo.etat.blocs = b.geo.table.taille; b.geo.cache.clear();
let graine = 7;
const hasard = () => ((graine = (graine * 16807) % 2147483647) / 2147483647);
const POIDS = { CN: 9, RU: 7, US: 5, NL: 4, DE: 3, IN: 3, BR: 2, KR: 2, SG: 2, LT: 2, RO: 2, BG: 1, VN: 1, CH: 1, AU: 1, ZA: 1, AR: 1 };
const sourcesDemo = BLOCS.flatMap(([d, , cc]) => Array.from({ length: Math.max(1, Math.round((POIDS[cc] || 1) * 1.5)) }, (_, i) => ({ ip: d.split('.').slice(0, 3).join('.') + '.' + (7 + i * 13), poids: (POIDS[cc] || 1) * (1 + hasard() * 3) })));
const CIBLES = [['192.0.2.10', 'force-brute', 22], ['192.0.2.10', 'web', 443], ['192.0.2.11', 'intrusion', 80], ['192.0.2.11', 'force-brute', 22], ['192.0.2.20', 'intrusion', 3389], ['192.0.2.50', 'pare-feu', 23], ['192.0.2.1', 'pare-feu', 8443]];
const maintenant = Date.now();
for (let hh = 23; hh >= 0; hh--) {
  const vague = 0.6 + 0.4 * Math.sin(hh / 3.2) + (hh === 4 ? 1.8 : 0);
  for (const src of sourcesDemo) {
    if (hasard() > 0.55) continue;
    const [cible, nature, port] = CIBLES[Math.floor(hasard() * CIBLES.length)];
    const coups = Math.round(src.poids * vague * (2 + hasard() * 18));
    for (let k = 0; k < coups; k++) b.carnet.noter({ quand: maintenant - hh * 3600e3 - Math.floor(hasard() * 3500e3), ip: src.ip, cible, port, nature });
  }
}
b.carnet.vider();
const lesPlus = b.carnet.resume({ heures: 24 }).top.slice(0, 14);
for (const t of lesPlus.slice(1)) await b.riposte.bloquer({ ip: t.ip, motif: `${t.natures[0] === 'force-brute' ? 'force brute' : t.natures[0] === 'intrusion' ? 'IPS : tentative d’exploitation' : 'balayage de ports'} (${t.n} coups en 24 h)`, raisons: ['score au-dessus du seuil'], score: 140, auteur: 'vigie', automatique: true });
console.log(`VIGIE de démonstration sur http://localhost:${port} — jeton d’installation : ${jeton}`);
