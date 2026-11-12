// La sentinelle de VIGIE : les journaux des hôtes du réseau (SSH, sudo, comptes,
// NAS, hyperviseur, serveurs web, conteneurs, noyau…) arrivent par le même
// récepteur syslog que la passerelle ; le moteur (moteur.js) leur donne un
// niveau. Ici, ce que VIGIE en fait : garder les alertes, nourrir le bouclier
// (une adresse qui force un compte prend des points, un hôte qui montre des
// signes de compromission aussi), lever un événement, et diffuser le flux en
// direct à l'interface.
import { Sentinelle } from './moteur.js';
import { REGLES, gravite } from './regles.js';
import { NOMS_DECODEURS } from './decodeurs.js';
import { estPublique, estInterne } from '../bouclier/ip.js';
import { natureAlerte } from '../bouclier/carnet.js';

const MAX_ABONNES = 32;
const POINTS = n => n >= 15 ? 120 : n >= 13 ? 100 : n >= 12 ? 80 : n >= 11 ? 70 : n >= 10 ? 60 : 0;

export class SentinelleVigie {
  constructor({ magasin, moteur, bouclier, log = console, maintenant = () => Date.now() }) {
    Object.assign(this, { magasin, moteur, bouclier, log, maintenant });
    let cache = { t: 0, r: null };
    this.reglage = () => { const t = Date.now(); if (!cache.r || t - cache.t > 5000) cache = { t, r: magasin.reglage('sentinelle') }; return cache.r; };
    this.rafraichir = () => { cache = { t: 0, r: null }; };
    this.abonnes = new Set();
    this.tampon = [];           // les 200 derniers messages du flux, pour un abonné qui arrive
    this.compteFlux = 0;
    this.moteurSentinelle = new Sentinelle({
      maintenant, log,
      seuil: () => this.reglage().seuil,
      vus: { vu: c => magasin.sentinelleVu(c), noter: c => magasin.sentinelleNoterVu(c) },
      surEvenement: e => this.diffuser('sentinelle', e),
      surAlerte: a => this.surAlerte(a),
    });
  }

  /** Branché sur le récepteur syslog : toute ligne que le bouclier n'a pas reconnue. */
  ligne(texte, emetteur, t) {
    if (!this.reglage().actif) return false;
    return this.moteurSentinelle.traiter(texte, { emetteur, quand: t }).lue;
  }

  /** Les observations du bouclier passent aussi dans le flux : une seule fenêtre sur tout ce qui bouge. */
  observation(o) { this.diffuser('bouclier', { quand: o.quand, type: o.type, src: o.src, dst: o.dst, dport: o.dport, proto: o.proto, action: o.action, signature: o.signature, gravite: o.gravite, capteur: o.capteur }); }

  surAlerte(a) {
    const r = this.reglage();
    // L'heure gardée est celle de la réception : l'horodatage d'un journal est celui de l'hôte, parfois faux ou vieux.
    try { this.magasin.sentinelleAlerte({ ...a, quand: a.recu || a.quand }); } catch (e) { this.log.warn?.(`[sentinelle] base : ${e.message}`); }
    const ip = a.champs.srcip;
    const points = POINTS(a.niveau);
    // Le carnet des attaques : une alerte venue d'une adresse publique, sur l'hôte qui l'a journalisée.
    if (ip && this.bouclier?.carnet) this.bouclier.carnet.noter({ quand: a.recu || a.quand, ip, cible: a.hote || a.emetteur || '', port: Number(a.champs.dport || a.champs.port) || 0, nature: natureAlerte(a.groupes) });
    // Le bouclier : l'adresse qui attaque prend des points ; l'hôte qui montre
    // des signes de compromission aussi, par l'adresse qui nous a envoyé son journal.
    if (r.correler && this.bouclier && points) {
      const c = this.bouclier.correlateur;
      // Les journaux d'hôtes arrivent par le syslog : sans émetteur déclaré, n'importe quelle machine du réseau a pu les écrire.
      const obs = { type: 'sentinelle', quand: a.quand, capteur: `syslog:${a.emetteur}`, hote: a.hote, regle: a.regle, verifie: (this.magasin.reglage('bouclier').emetteurs || []).length > 0 };
      const raison = `${a.description} (${a.hote || a.emetteur}${a.champs.utilisateur ? `, compte ${a.champs.utilisateur}` : ''})`;
      if (ip && estPublique(ip)) c.noter(ip, { points, raison, cle: `sentinelle:${a.regle}`, observation: obs });
      else if (ip && estInterne(ip) && ip !== a.emetteur && a.groupes.some(g => ['force-brute', 'balayage', 'web-attaque'].includes(g))) {
        // Une machine du réseau qui en attaque une autre : mouvement latéral.
        c.noter(ip, { interne: true, points, raison: `mouvement latéral : ${raison}`, cle: `sentinelle:${a.regle}`, observation: obs });
      }
      if (a.groupes.includes('compromission') && a.emetteur && estInterne(a.emetteur)) {
        c.noter(a.emetteur, { interne: true, points: Math.max(points, 60), raison: `hôte compromis : ${a.description}`, cle: `sentinelle-hote:${a.regle}`, observation: obs });
      }
    }
    if (a.niveau >= r.seuilEvenement && this.moteur) {
      const sujet = a.hote || a.emetteur || '';
      const qui = [ip && `depuis ${ip}`, a.champs.utilisateur && `compte ${a.champs.utilisateur}`, a.champs.commande && `commande : ${a.champs.commande.slice(0, 120)}`, a.champs.url && `URL : ${a.champs.url.slice(0, 120)}`].filter(Boolean).join(' · ');
      this.moteur.signaler({
        gravite: gravite(a.niveau), type: 'sentinelle', sujet,
        titre: `${sujet} : ${a.description}`.slice(0, 300),
        texte: `Niveau ${a.niveau} (règle ${a.regle}, ${a.programme || a.decodeur || 'journal'})${qui ? ' — ' + qui : ''}. Extrait : ${a.extrait.slice(0, 300)}`,
        cle: `sentinelle:${a.regle}:${sujet}:${ip || a.champs.utilisateur || ''}`,
      }).catch(e => this.log.warn?.(`[sentinelle] ${e.message}`));
    }
  }

  // Flux en direct (SSE)
  diffuser(genre, corps) {
    const m = { n: ++this.compteFlux, genre, ...corps };
    this.tampon.push(m); if (this.tampon.length > 200) this.tampon.shift();
    if (!this.abonnes.size) return;
    const ligne = `id: ${m.n}\nevent: ${genre}\ndata: ${JSON.stringify(m)}\n\n`;
    for (const res of this.abonnes) { try { res.write(ligne); } catch { this.abonnes.delete(res); } }
  }
  abonner(res, depuis = 0) {
    if (this.abonnes.size >= MAX_ABONNES) throw Object.assign(new Error('Trop de flux ouverts.'), { status: 429 });
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no' });
    res.write('retry: 3000\n\n');
    for (const m of this.tampon) if (m.n > depuis) res.write(`id: ${m.n}\nevent: ${m.genre}\ndata: ${JSON.stringify(m)}\n\n`);
    this.abonnes.add(res);
    const fin = () => { this.abonnes.delete(res); clearInterval(battement); };
    const battement = setInterval(() => { try { res.write(': battement\n\n'); } catch { fin(); } }, 25_000);
    battement.unref?.();
    res.on('close', fin); res.on('error', fin);
  }

  // Vues
  etat() {
    const m = this.moteurSentinelle.etat();
    const r = this.reglage();
    const jour = this.maintenant() - 86400e3;
    return {
      actif: r.actif, seuil: r.seuil, seuilEvenement: r.seuilEvenement, correler: r.correler,
      port: this.bouclier?.cfg?.syslogPortHote || this.bouclier?.cfg?.syslogPort || null,
      stats: m.stats, hotes: m.hotes, regles: m.regles, nbRegles: m.nbRegles, decodeurs: NOMS_DECODEURS,
      recentes: this.moteurSentinelle.recents.slice(0, 60).map(resume),
      bilan: this.magasin.sentinelleBilan(jour),
      abonnes: this.abonnes.size,
    };
  }
  alertes(q) { return this.magasin.sentinelleAlertes(q); }
  regles() { return REGLES.map(r => ({ id: r.id, niveau: r.niveau, gravite: gravite(r.niveau), groupes: r.groupes, description: r.description, si: r.si || null, frequence: r.frequence || null, fenetre: r.fenetre || null, meme: r.meme || null, apres: r.apres || null, fts: r.fts || null, ignorer: r.ignorer || null, silence: !!r.silence })); }
  essai(ligne) { return this.moteurSentinelle.essai(ligne); }

  demarrer() {
    const purger = () => { try { this.magasin.sentinellePurger(this.reglage().retentionJours || 30); } catch (e) { this.log.warn?.(`[sentinelle] purge : ${e.message}`); } };
    this.tPurge = setTimeout(purger, 60_000); this.tPurge.unref?.();
    this.iPurge = setInterval(purger, 6 * 3600e3); this.iPurge.unref?.();
    return this;
  }
  arreter() { clearTimeout(this.tPurge); clearInterval(this.iPurge); for (const res of this.abonnes) { try { res.end(); } catch { /* fermé */ } } this.abonnes.clear(); }
}

const resume = a => ({ quand: a.quand, hote: a.hote, programme: a.programme, regle: a.regle, niveau: a.niveau, gravite: a.gravite, groupes: a.groupes, description: a.description, srcip: a.champs.srcip || '', utilisateur: a.champs.utilisateur || '', champs: a.champs, extrait: a.extrait });
