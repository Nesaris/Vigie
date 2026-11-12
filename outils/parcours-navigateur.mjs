// Parcours réel de VIGIE dans Chromium (clé d'accès virtuelle) : installation
// par la porte du socle, chaque page et ses dialogues, contrôle de mise en page
// à chaque largeur. Contre la vitrine (outils/vitrine.mjs) :
//   node outils/parcours-navigateur.mjs http://localhost:8197 JETON DOSSIER
import { chromium } from 'playwright';
import fs from 'node:fs';
import { chevauchements, LARGEURS } from '../socle/essai/mise-en-page.mjs';
import { passerAssistant, ouvrirReglagesService } from '../socle/essai/assistant-navigateur.mjs';

const [base, jeton, sortie = '/tmp/captures-vigie'] = process.argv.slice(2);
fs.mkdirSync(sortie, { recursive: true });
const navigateur = await chromium.launch();
const contexte = await navigateur.newContext({ viewport: { width: 1280, height: 860 }, colorScheme: process.env.PARCOURS_SOMBRE === '1' ? 'dark' : 'light' });
const page = await contexte.newPage();
const erreurs = [];
page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource.*(404|401)/.test(m.text())) erreurs.push(m.text()); });
page.on('pageerror', e => erreurs.push(String(e)));
page.on('response', r => { if (r.status() === 400 || r.status() >= 500) erreurs.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });
const cdp = await contexte.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

const rapport = [];
async function controle(nom) {
  for (const w of LARGEURS) {
    await page.setViewportSize({ width: w, height: w < 500 ? 780 : 900 });
    await page.waitForTimeout(250);
    rapport.push({ ecran: nom, largeur: w, defauts: await page.evaluate(chevauchements) });
    if ([360, 768, 1280].includes(w)) await page.screenshot({ path: `${sortie}/${nom}-${w}.png`, fullPage: true });
  }
  await page.setViewportSize({ width: 1280, height: 860 });
  await page.waitForTimeout(150);
}
const aller = async (titre, entete = titre) => {
  await page.getByRole('button', { name: titre, exact: true }).first().click();
  await page.getByRole('heading', { name: entete, exact: true }).first().waitFor();
  await page.waitForTimeout(400);
};
const dialogue = () => page.getByRole('dialog').last();
const fermer = async () => { await dialogue().getByRole('button', { name: /^(Annuler|Fermer)$/ }).last().click(); await page.waitForTimeout(200); };

await page.goto(base);
await page.getByText('Premier compte').waitFor();
await controle('installation');
await page.getByLabel('Jeton d’installation').fill(jeton);
await page.getByLabel('Identifiant').fill('ana');
await page.getByLabel('Mot de passe').fill('phrase de passe pour la vigie de la vitrine');
await page.getByRole('button', { name: 'Créer le compte' }).click();
await page.getByRole('button', { name: /Créer la clé maintenant/ }).click();
await page.getByText('J’ai rangé ces codes en lieu sûr.').click();
await page.getByRole('button', { name: 'Terminer' }).click();
await passerAssistant(page, { controle });
await page.getByRole('heading', { name: 'Votre réseau', exact: true }).waitFor();
await page.locator('svg.monde').waitFor();
await page.waitForTimeout(800);
await controle('accueil');
await aller('Attaques');
await page.locator('svg.flux').waitFor();
await controle('attaques');
for (const periode of ['7 jours', '1 h']) {
  await page.getByRole('tab', { name: periode, exact: true }).click();
  await page.waitForTimeout(500);
  await controle(`attaques-${periode.replace(' ', '')}`);
}
await aller('Posture', 'Posture de sécurité');
await page.waitForTimeout(800);
await controle('tableau');
await aller('Constats');
await controle('constats');
await page.locator('.flowrow.cliquable').first().click();
await dialogue().waitFor();
await page.waitForTimeout(300);
await controle('fiche-constat');
await fermer();
await page.getByRole('button', { name: 'Par hôte' }).click();
await page.locator('details.hote').first().locator('summary').click();
await page.waitForTimeout(300);
await controle('constats-hotes');
await aller('Historique');
await controle('historique');
await aller('Bouclier');
await controle('bouclier');
await page.getByRole('button', { name: 'Bloquer une adresse' }).click();
await dialogue().waitFor();
await controle('bouclier-bloquer');
await fermer();
// Chaque liste du Bouclier a sa page (#bouclier?vue=…), ouverte depuis l'ensemble.
const vueDetail = async (ouvrir, entete, nom) => {
  await ouvrir();
  await page.getByRole('heading', { name: entete, exact: true }).first().waitFor();
  await page.waitForTimeout(400);
  await controle(nom);
};
const enTete = nom => page.locator('.headrow').getByRole('button', { name: nom, exact: true }).click();
const toutVoir = titre => page.locator('.card', { has: page.getByRole('heading', { name: titre, exact: true }) }).getByRole('button', { name: 'Tout voir' }).click();
await vueDetail(() => page.locator('.fig.cliquable', { hasText: 'Menaces suivies' }).click(), 'Menaces extérieures', 'bouclier-menaces');
await aller('Bouclier');
await vueDetail(() => page.getByRole('button', { name: /^Blocages en cours/ }).click(), 'Blocages', 'bouclier-blocages');
await aller('Bouclier');
await vueDetail(() => toutVoir('Machines du réseau'), 'Machines du réseau', 'bouclier-machines');
await aller('Bouclier');
await vueDetail(() => page.getByRole('button', { name: /^Alertes de l’IPS ·/ }).click(), 'Alertes de l’IPS', 'bouclier-alertes');
await aller('Bouclier');
await vueDetail(() => enTete('Réglages'), 'Réglages du bouclier', 'bouclier-reglages');
await aller('Sentinelle');
await controle('sentinelle');
await vueDetail(() => toutVoir('En direct'), 'En direct', 'sentinelle-direct');
await aller('Sentinelle');
await vueDetail(() => toutVoir('Dernières alertes'), 'Alertes', 'sentinelle-alertes');
await aller('Sentinelle');
await vueDetail(() => toutVoir('Hôtes les plus exposés'), 'Hôtes', 'sentinelle-hotes');
await aller('Sentinelle');
await vueDetail(async () => {
  await page.getByRole('button', { name: 'Sources d’attaque et règles' }).click();
  await page.locator('details.regles-ref > summary').click();
  await page.locator('.famille').first().waitFor();
}, 'Sources et règles', 'sentinelle-sources');
await aller('Sentinelle');
await vueDetail(async () => {
  await enTete('Réglages');
  await page.getByLabel('Ligne de journal').fill('<38>Oct 15 10:00:01 serveur sshd[1234]: Failed password for root from 203.0.113.7 port 51234 ssh2');
  await page.getByRole('button', { name: 'Analyser' }).click();
  await page.locator('dl.preuve').waitFor();
}, 'Réglages de la sentinelle', 'sentinelle-reglages');
await aller('Événements');
await controle('evenements');
await aller('Actions');
await controle('actions');
await aller('Réglages');
await controle('reglages');
await aller('Sécurité');
await controle('securite');
await aller('Comptes');
await controle('comptes');

const defauts = rapport.filter(r => r.defauts.length);
fs.writeFileSync(`${sortie}/rapport.json`, JSON.stringify({ rapport, erreurs }, null, 2));
console.log(`écrans×largeurs contrôlés : ${rapport.length}, avec défauts : ${defauts.length}, erreurs console : ${erreurs.length}`);
for (const r of defauts) for (const d of r.defauts.slice(0, 4)) console.log(`  ${r.ecran} @${r.largeur} — ${d.type} : ${d.detail}`);
for (const e of erreurs) console.log('  console :', e);
await navigateur.close();
process.exit(defauts.length || erreurs.length ? 1 : 0);
