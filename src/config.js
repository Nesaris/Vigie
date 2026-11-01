// Configuration de VIGIE, lue et validée une fois au démarrage. Les variables
// SOCLE_* (comptes, relais, clé maîtresse) sont lues par le socle. Une valeur
// invalide arrête le processus avec la liste complète des erreurs.
//
// Les adresses et jetons des sources viennent du Hub (capacités du manifeste) :
// chaque service donne à VIGIE un jeton dérivé pour lui seul — jamais le jeton
// qu'il partage avec le Hub.
import { lireConfig } from '../socle/src/index.js';

export const VERSION = '1.3.1';

const URL_OU_VIDE = { type: 'url', defaut: '' };
const DERIVE = /^cer_[a-z0-9][a-z0-9-]{1,30}_[0-9a-f]{64}$/;

export const SPEC_VIGIE = {
  port: { env: 'PORT', type: 'entier', min: 0, max: 65535, defaut: 8170 },
  hote: { env: 'HOTE', type: 'chaine', defaut: '0.0.0.0' },
  // Récepteur syslog du bouclier (UDP et TCP) dans le conteneur, et le port
  // publié sur la machine, celui à donner à la passerelle. 0 : pas de récepteur.
  syslogPort: { env: 'VIGIE_SYSLOG_PORT', type: 'entier', min: 0, max: 65535, defaut: 5514 },
  syslogPortHote: { env: 'VIGIE_SYSLOG_PORT_HOTE', type: 'entier', min: 0, max: 65535, defaut: 0 },
  donnees: { env: 'DATA_DIR', type: 'chaine', defaut: '/data' },
  // Jeton du Hub : actions, sondes et déclencheurs. Il sert aussi à vérifier
  // les jetons dérivés que le Hub donne aux services voisins (MapMyLAN).
  jetonHub: { env: 'VIGIE_HUB_TOKEN', type: 'secret', min: 24 },
  // Les sources. MapMyLAN est requis par le manifeste ; les autres, facultatives.
  mapmylanUrl: { env: 'MAPMYLAN_URL', ...URL_OU_VIDE },
  mapmylanJeton: { env: 'MAPMYLAN_JETON', type: 'chaine', motif: DERIVE, defaut: '' },
  nexarcUrl: { env: 'NEXARC_URL', ...URL_OU_VIDE },
  nexarcJeton: { env: 'NEXARC_JETON', type: 'chaine', motif: DERIVE, defaut: '' },
  dockerUrl: { env: 'DOCKER_CONTROL_URL', ...URL_OU_VIDE },
  // L'IA locale (Ollama du Hub) et son modèle par défaut.
  iaLocaleUrl: { env: 'IA_LOCALE_URL', ...URL_OU_VIDE },
  iaLocaleModele: { env: 'IA_LOCALE_MODELE', type: 'chaine', motif: /^[\w.:/-]{1,120}$/, defaut: '' },
  // Le moteur d'IA choisi depuis le Hub (installation) : appliqué au démarrage
  // quand il change ; les réglages de VIGIE le précisent ensuite.
  iaMode: { env: 'VIGIE_IA_MODE', type: 'choix', parmi: ['', 'aucune', 'locale', 'cloud', 'les-deux', 'secours'], defaut: '' },
  iaFournisseur: { env: 'VIGIE_IA_FOURNISSEUR', type: 'choix', parmi: ['anthropic', 'openai', 'kimi'], defaut: 'anthropic' },
  iaModeleLocal: { env: 'VIGIE_IA_MODELE_LOCAL', type: 'chaine', motif: /^[\w.:/-]{1,120}$/, defaut: '' },
  iaModeleCloud: { env: 'VIGIE_IA_MODELE', type: 'chaine', motif: /^[\w.:/-]{1,120}$/, defaut: '' },
  iaCle: { env: 'VIGIE_IA_CLE', type: 'secret', min: 20 },
  iaAppelsJour: { env: 'VIGIE_IA_APPELS_JOUR', type: 'entier', min: 0, max: 1000, defaut: 20 },
  // SYNAPSE : mémoire des audits et des interventions.
  synapseUrl: { env: 'SYNAPSE_URL', ...URL_OU_VIDE },
  synapseJeton: { env: 'SYNAPSE_JETON', type: 'chaine', motif: DERIVE, defaut: '' },
  // API des IA en nuage (remplacées dans les essais).
  anthropicApi: { env: 'VIGIE_ANTHROPIC_API', type: 'url', defaut: 'https://api.anthropic.com' },
  openaiApi: { env: 'VIGIE_OPENAI_API', type: 'url', defaut: 'https://api.openai.com' },
  kimiApi: { env: 'VIGIE_KIMI_API', type: 'url', defaut: 'https://api.moonshot.ai' },
  tgApi: { env: 'VIGIE_TELEGRAM_API', type: 'url', defaut: 'https://api.telegram.org' },
};

// Ce que l'assistant de configuration demande (première installation, puis
// seulement les réglages nouveaux d'une mise à jour). depuis : la version qui
// a ajouté le réglage. Installé par le Hub, VIGIE reçoit ses sources de lui.
export const REGLAGES_VIGIE = [
  { env: 'MAPMYLAN_URL', groupe: 'Sources', libelle: 'Adresse de MapMyLAN', exemple: 'http://mapmylan:8090', depuis: '1.3.0',
    aide: 'L’inventaire du réseau que VIGIE audite. Vide : pas d’inventaire, seulement les journaux reçus.' },
  { env: 'MAPMYLAN_JETON', groupe: 'Sources', libelle: 'Jeton de MapMyLAN pour VIGIE', secret: true, depuis: '1.3.0', aide: 'Jeton dérivé pour VIGIE seul (docs/INTEGRATION.md).' },
  { env: 'NEXARC_URL', groupe: 'Sources', libelle: 'Adresse de NEXARC', exemple: 'http://nexarc:8090', depuis: '1.3.0', aide: 'Facultatif : l’état des machines gérées.' },
  { env: 'NEXARC_JETON', groupe: 'Sources', libelle: 'Jeton de NEXARC pour VIGIE', secret: true, depuis: '1.3.0' },
  { env: 'VIGIE_SYSLOG_PORT_HOTE', groupe: 'Bouclier', libelle: 'Port syslog publié sur la machine', exemple: '5514', depuis: '1.3.0',
    aide: 'Le port à donner à la passerelle pour ses journaux. 0 : pas de récepteur annoncé.' },
  { env: 'VIGIE_IA_MODE', groupe: 'Intelligence artificielle', libelle: 'IA des audits', depuis: '1.3.0',
    noms: { '': 'Réglée dans VIGIE', aucune: 'Aucune', locale: 'Locale (Ollama)', cloud: 'En nuage', 'les-deux': 'Les deux', secours: 'Locale, nuage en secours' },
    aide: 'Le moteur qui rédige les audits. Se précise ensuite dans les réglages de VIGIE.' },
  { env: 'IA_LOCALE_URL', groupe: 'Intelligence artificielle', libelle: 'Adresse d’Ollama', exemple: 'http://ollama:11434', depuis: '1.3.0' },
  { env: 'IA_LOCALE_MODELE', groupe: 'Intelligence artificielle', libelle: 'Modèle local', exemple: 'qwen3:14b', depuis: '1.3.0' },
  { env: 'VIGIE_IA_FOURNISSEUR', groupe: 'Intelligence artificielle', libelle: 'Fournisseur en nuage', noms: { anthropic: 'Anthropic', openai: 'OpenAI', kimi: 'Kimi' }, depuis: '1.3.0' },
  { env: 'VIGIE_IA_MODELE', groupe: 'Intelligence artificielle', libelle: 'Modèle en nuage', depuis: '1.3.0' },
  { env: 'VIGIE_IA_CLE', groupe: 'Intelligence artificielle', libelle: 'Clé d’API du fournisseur', depuis: '1.3.0' },
  { env: 'VIGIE_IA_APPELS_JOUR', groupe: 'Intelligence artificielle', libelle: 'Appels par jour au plus', depuis: '1.3.0', avance: true, aide: 'Plafond de dépense de l’IA en nuage.' },
];

export function lireConfigVigie(env = process.env) {
  return lireConfig(SPEC_VIGIE, env);
}
