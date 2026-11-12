# Security compliance — VIGIE

Standard: Project Baseline Requirements & Security Manual, Edition 2.0 (258 controls)
Audited: 2026-10-19   ·   Owner: Codex64   ·   Status: NON-COMPLIANT

## Summary
| Part | Controls | Pass | Fail | N/A | Unknown |
|---|---|---|---|---|---|
| I — Baseline requirements | 68 | 53 | 13 | 2 | 0 |
| II — Security controls | 190 | 96 | 29 | 65 | 0 |
| Total | 258 | 149 | 42 | 67 | 0 |

## Authentication posture
Les opérateurs passent par le socle commun, embarqué avec ses essais et vérifié par ses empreintes : quatre facteurs cumulables sur chaque compte — mot de passe (Argon2id, 64 Mio, 3 passes, parallélisme 4, plancher 19 Mio / 2 / 1, rehachage transparent, liste de fuites locale, 12 à 1024 caractères), application TOTP (RFC 6238, secret scellé AES-256-GCM, rejeu refusé), clés d’accès WebAuthn (clé résidente, vérification de l’utilisateur exigée, vingt par compte) et dix codes de secours de 100 bits hachés en Argon2id ; politique par facteur réglable sans déploiement, clé d’accès requise pour les administrateurs par défaut. Sessions serveur de 256 bits en cookie __Host-, HttpOnly, Secure, SameSite=Strict, douze heures au plus et une heure d’inactivité, renouvelées à chaque changement de niveau, listées par appareil et fermables une à une ou toutes en une requête. Renfort (re-vérification récente) pour les gestes qui ouvrent, coupent ou détournent : réaction rapide, isolation forcée, veille et sentinelle, bouclier, passerelle et Cloudflare, jetons de sonde et de liste, clés et destinations des alertes. Les machines n’ont pas de session : le Hub présente son jeton (lecture, audits, actions, jamais les réglages), un service voisin un jeton dérivé par HMAC (lecture et audit), une sonde Suricata son jeton gardé par son empreinte ; chaque échec compte dans le limiteur persistant du socle.

## Findings (audit of 1.2.6, fixed in 1.2.7)
VIGIE 1.2.6 relue en lecture seule le 2026-10-19 (code, essais, balayage de l’annexe B, cassures volontaires, sondage exploratoire), classée par gravité ; chaque constat corrigé par le commit indiqué, avec son essai de non-régression.

| # | Gravité | Contrôles | Constat | Commits |
|---|---|---|---|---|
| C1 | HIGH | SEC-AUTHZ-007, REQ-WEB-005, SEC-LLM-005 | Sans émetteur déclaré (le défaut), toute adresse privée était lue par le récepteur syslog, et une seule ligne CEF forgée de gravité 1 faisait bloquer seule une adresse extérieure à la frontière, par UniFi et Cloudflare (mode Under Attack compris pour une tempête), ou isoler une machine du réseau par la réaction rapide. Ce que dit un émetteur non déclaré est désormais signalé, jamais suivi d’effet automatique. | 1b284dc |
| C2 | HIGH | REQ-WEB-008, SEC-API-002 | Expression régulière du décodeur Wi-Fi non ancrée : une ligne de 16 Kio, envoyée par n’importe quel émetteur accepté, figeait le processus un quart de seconde ; quelques lignes par seconde rendaient VIGIE muette. | d6c62ad |
| C3 | MEDIUM | REQ-WEB-008 | Le débit du récepteur comptait les lignes refusées : une inondation venue d’un émetteur non déclaré faisait déborder la passerelle déclarée. | 4e8053c |
| C4 | MEDIUM | REQ-SESS-005, SEC-SESS-007 | Couper la veille ou la sentinelle, relever leurs seuils, et changer la conversation Telegram où partent les alertes se faisaient sans renfort. | 13996c7 |
| C5 | MEDIUM | REQ-WEB-008, SEC-API-010 | Réponses des voisins, des IA, de Cloudflare lues sans borne ; les listes de menaces téléchargées en entier avant d’en contrôler la taille. | 9471574 |
| C6 | MEDIUM | REQ-WEB-005, SEC-CSRF-004 | Billetterie et listes de menaces ajoutées pouvaient viser le lien local et les métadonnées d’un nuage (en https, ou par un nom qui y mène), et les listes suivaient les redirections. | 0bbd71a |
| C7 | MEDIUM | REQ-CFG-005, SEC-SECRETS-006 | Après une rotation de SOCLE_CLE, les secrets des réglages (IA, Telegram, billetterie, UniFi, Cloudflare) restaient scellés sous l’ancienne clé et devenaient illisibles. | 3c18380 |
| C8 | MEDIUM | REQ-DATA-003, SEC-DB-006, SEC-LOG-007 | Aucune sauvegarde chiffrée ni retrait des secrets pour un incident ; en installation seule, la clé maîtresse vivait dans le volume de données. | 9e32292, 33d3e96 |
| C9 | MEDIUM | REQ-DATA-006, SEC-PRIV-004, SEC-PRIV-001 | L’identifiant d’un compte supprimé restait dans les audits, actions, acquittements et blocages, absents de son export ; actions gardées sans limite ; notice de confidentialité sans durées ni destinataires complets. | 3025bd3, 2390c32, 1406c89 |
| C10 | MEDIUM | REQ-DATA-004 | Un isolement tenté par un membre, ou un jeton sorti de sa portée, était refusé sans laisser de trace au journal de sécurité. | 4d4f5e9 |
| C11 | LOW | REQ-WEB-006 | Un paramètre de requête inconnu passait quand la route rendait avant de lire ses paramètres. | 1459001 |
| C12 | LOW | — (détection) | Un refus 802.1X du Wi-Fi était lu comme une association : la règle « wifi.echec » ne se déclenchait jamais. | caec3ba |
| C13 | LOW | REQ-ANON-007 | Modèles d’équipement de l’auteur nommés dans des commentaires, des essais et la vitrine. | f2ae7e0 |
| C14 | LOW | REQ-CI-006, REQ-CODE-005 | Essais : seules cinq routes balayées pour les droits, aucun essai des en-têtes ; cinq cassures volontaires passaient inaperçues. | 98eef4d, fe59492, f4df560 |
| C15 | LOW | SEC-DEP-004 | Aucune mise à jour proposée par Dependabot ; actions de CI en retard d’une version. | da5a243 |

## Control status
| ID | Severity | Status | Evidence | Notes |
|---|---|---|---|---|
| REQ-AUTH-001 | CRITICAL | PASS | `socle/src/comptes.js:25` ; mot de passe, TOTP, clés et codes de secours cumulables : essai `socle/test/parcours.test.js:159` | socle embarqué, ses essais rejoués par la vérification de VIGIE (`.github/workflows/verification.yml:30`) ; QR code du TOTP dessiné dans le navigateur (`socle/web/qr.js:240`) |
| REQ-AUTH-002 | CRITICAL | PASS | `socle/src/comptes.js:28` ; `socle/src/index.js:49` ; réglable sans déploiement : `socle/src/portail.js:476` | défaut : mot de passe et TOTP facultatifs, clé requise pour les administrateurs |
| REQ-AUTH-003 | CRITICAL | PASS | `socle/src/webauthn.js:26` ; vingt clés nommées : `socle/src/comptes.js:39` ; renommer et retirer : `socle/src/portail.js:316` | liste avec dates de création et d’usage dans la page Sécurité |
| REQ-AUTH-004 | CRITICAL | PASS | `socle/src/webauthn.js:46` ; origine `socle/src/webauthn.js:47` ; rpIdHash `socle/src/webauthn.js:103` | défi à usage unique lié à la session, UP et UV exigés, signature et compteur vérifiés |
| REQ-AUTH-005 | CRITICAL | PASS | `socle/src/comptes.js:732` ; renfort et fermeture des autres sessions : `socle/src/comptes.js:748` | la notification part à l’adresse vérifiée quand un relais existe (voir REQ-AUTH-014) |
| REQ-AUTH-006 | CRITICAL | PASS | `socle/src/comptes.js:993` ; jeton de 20 minutes, haché, unique : `socle/src/comptes.js:37` | essai `socle/test/parcours.test.js:242` ; rejoué par le runbook (`outils/exercice-incident.mjs:70`) |
| REQ-AUTH-007 | HIGH | PASS | `socle/src/comptes.js:40` ; 100 bits, haché Argon2id, usage unique : `socle/src/comptes.js:532` | alerte « secours.utilise » (courriel si relais, voir REQ-AUTH-014) |
| REQ-AUTH-008 | HIGH | PASS | `socle/src/totp.js:35` ; rejeu refusé : `socle/src/comptes.js:624` | RFC 6238, 6 chiffres, 30 s, ±1 pas, secret scellé AES-256-GCM |
| REQ-AUTH-009 | CRITICAL | PASS | aucune voie SMS ni code par courriel : `grep -rniE "sms\|twilio" socle/src src` → 0 ; connexions possibles : `socle/src/comptes.js:465`, `socle/src/comptes.js:491`, `socle/src/comptes.js:513`, `socle/src/comptes.js:578` | un mot de passe seul n’ouvre qu’une session d’inscription ; le jeton du Hub n’ouvre jamais de session humaine |
| REQ-AUTH-010 | CRITICAL | PASS | humains : `socle/src/limiteur.js:20` (SQLite, par adresse et par compte, paliers de verrou, preuve de travail après trois échecs) ; jetons du Hub, dérivés, de sonde et de liste : chaque échec compte pour l’adresse dans le même limiteur persistant (`src/api.js:112`, `src/api.js:122`) : dix échecs bloquent l’adresse, même pour le bon jeton | essai `test/vigie.test.js:712` |
| REQ-AUTH-011 | HIGH | PASS | vérification leurre : `socle/src/argon.js:110` ; message unique | essai `socle/test/parcours.test.js:81` |
| REQ-AUTH-012 | HIGH | PASS | `socle/src/comptes.js:1032` : l’adresse n’existe que dans le jeton haché tant qu’elle n’est pas vérifiée ; `socle/src/comptes.js:1041` | l’adresse ne sert qu’aux alertes : ni identifiant, ni récupération, ni droit ; pas d’inscription libre (invitation seulement) |
| REQ-AUTH-013 | HIGH | PASS | `socle/src/comptes.js:831` | le premier compte naît administrateur et doit inscrire une clé avant tout accès complet (en HTTPS) |
| REQ-AUTH-014 | MEDIUM | FAIL | `socle/src/notifications.js:97` ; « ce n’était pas moi » : `socle/src/comptes.js:1019` | implémenté et essayé (`socle/test/courriel.test.js:63`) ; ne part que si un relais SMTP est configuré → action H2 |
| REQ-CRYPT-001 | CRITICAL | PASS | `socle/src/argon.js:15` ; 64 Mio, t=3, p=4 par défaut : `socle/src/index.js:42` | Argon2id natif de Node, sel de 16 octets par empreinte |
| REQ-CRYPT-002 | HIGH | PASS | `socle/src/argon.js:72` ; écrit dans la même requête : `socle/src/argon.js:129` | essai `socle/test/crypto.test.js:23` |
| REQ-CRYPT-003 | MEDIUM | N/A | bcrypt absent : `grep -rniE "bcrypt" socle/src src` → 0 ; Argon2id seul |  |
| REQ-CRYPT-004 | HIGH | PASS | `socle/src/motdepasse.js:12`, `socle/src/motdepasse.js:13`, liste de fuites locale `socle/src/motdepasse.js:18` | contrôlé côté serveur, sans règle de composition ni rotation forcée |
| REQ-CRYPT-005 | HIGH | PASS | `socle/src/outils.js:16` ; jetons de sonde de 264 bits (`src/api.js:460`) et de liste de 240 bits (`src/api.js:490`) ; jeton du Hub comparé en temps constant (`src/api.js:119`) ; jetons dérivés vérifiés par HMAC-SHA256 en temps constant (`src/api.js:85`) ; `grep -rnE "Math\.random\|uuidv1" src web` → 0 | références d’audits, de constats et d’actions de 72 bits, non secrètes (`src/base.js:11`) |
| REQ-CRYPT-006 | MEDIUM | PASS | jetons de sonde gardés par leur empreinte (`src/bouclier/index.js:12`), comparée en temps constant ; sessions : `socle/src/comptes.js:289` ; secrets que VIGIE doit pouvoir rejouer (clé d’IA, jetons Telegram, UniFi, Cloudflare, docker-control, clé de billetterie, jeton de liste) scellés, jamais hachés : voir REQ-DATA-002 | le jeton de liste se présente dans une URL (pare-feu qui ne savent pas envoyer d’en-tête) : il est scellé pour pouvoir être affiché à l’administrateur sous renfort |
| REQ-SESS-001 | CRITICAL | PASS | `socle/src/http.js:105` ; __Host- en HTTPS : `socle/src/portail.js:51` | aucune session dans le stockage du navigateur ; aucun cookie ne part vers les voisins : VIGIE présente à chacun son jeton dérivé, côté serveur (`src/sources.js:59`) |
| REQ-SESS-002 | CRITICAL | PASS | `socle/src/comptes.js:304` à la connexion, au renfort et à chaque changement de facteur ou de rôle | pas de jeton de rafraîchissement : sessions serveur |
| REQ-SESS-003 | HIGH | PASS | `socle/src/comptes.js:328` ; révocation : `socle/src/portail.js:325` et incident : `socle/src/portail.js:489` | appareil, adresse IP, première et dernière vue ; le flux en direct est réservé à une session (`src/api.js:523`) |
| REQ-SESS-004 | HIGH | PASS | `socle/src/comptes.js:750` ; déconnexion serveur : `socle/src/portail.js:276` | runbook : `outils/exercice-incident.mjs:58` |
| REQ-SESS-005 | HIGH | PASS | `socle/src/comptes.js:344` ; routes de VIGIE sous renfort (`grep -c "admin(ctx, true)" src/api.js` → 13, plus quatre renforts conditionnels) : réaction rapide, veille, sentinelle, périmètre, docker-control, bouclier, UniFi (sonde et réglage), Cloudflare et mode Under Attack, jetons de sonde et de liste ; clé d’IA et changement de fournisseur (`src/api.js:276`), billetterie (`src/api.js:328`), jeton et conversation Telegram (`src/api.js:342`), isolation forcée (`src/api.js:234`) | essai `test/vigie.test.js:414` |
| REQ-SESS-006 | MEDIUM | PASS | 12 h absolues, 60 min d’inactivité : `socle/src/index.js:40` | pas de JWT ; le flux en direct revérifie la session à son ouverture et se ferme avec elle |
| REQ-ANON-001 | CRITICAL | PASS | `git log --all --format="%an <%ae>" \| sort -u` et `--format="%cn <%ce>"` → une ligne chacun, le pseudonyme ; posée dans le dépôt : `git config --local user.name` → 1 | commits en UTC |
| REQ-ANON-002 | CRITICAL | FAIL | arbre : annexe B.1 → les adresses fabriquées des essais (10.9.x, plages de documentation) et le nom `.env.local` du `.gitignore` ; aucun terme de la liste d’anonymat propre à ce dépôt (la liste commune moins le nom d’un hyperviseur que la sentinelle sait lire) : `git grep` → 0 (annexe B.1.16) | l’historique publié garde des termes de la liste (modèles d’équipement, retirés de l’arbre par `f2ae7e0`) : seul l’exploitant peut décider d’une réécriture ou d’un dépôt neuf → action H12, détail dans le rapport hors dépôt |
| REQ-ANON-003 | CRITICAL | FAIL | liste et crochet global à poser sur le poste de développement ; contrôle CI par secret : `.github/workflows/verification.yml:85` | action H4 |
| REQ-ANON-004 | CRITICAL | PASS | commande de REQ-ANON-004 sur tout l’historique (`git log --all --format=%B \| grep -niE "co-authored-by\|generated with\|assistant\|claude\|copilot\|cursor\|gpt\|🤖"`) → 0 | contrôlé en CI sur chaque nouveau commit : `.github/workflows/verification.yml:60` |
| REQ-ANON-005 | HIGH | PASS | `package.json:6` sans champ auteur ; `LICENSE:1` | le README décrit le logiciel, jamais une machine ni une personne ; contact de sécurité : le signalement privé du dépôt (`src/main.js:24`) |
| REQ-ANON-006 | HIGH | PASS | `git log --all --name-only --format= \| grep -iE "\.(png\|jpe?g\|pdf\|mp4\|gif\|webp\|ico)$" \| wc -l` → 0 : aucune image ni document binaire dans tout l’historique ; l’icône est un SVG sans métadonnées (`web/icone.svg:1`) | polices WOFF2 du socle : métadonnées de la fonderie seulement ; captures du parcours gardées hors dépôt ; les rapports PDF sont produits à la demande, jamais commités |
| REQ-ANON-007 | HIGH | PASS | comptes « ana », « leo », « lea », « chloe » ; appareils et adresses de la plage de documentation (192.0.2.0/24, 203.0.113.0/24) et d’une plage 10.9 fabriquée ; jetons et clés d’essai fabriqués (`test/faux.js:12`) | les modèles de passerelle ont quitté commentaires, essais et vitrine (`f2ae7e0`) ; l’historique publié en garde la trace : voir « Anonymity » et le rapport hors dépôt |
| REQ-ANON-008 | MEDIUM | PASS | `git log --all --format=%aI \| grep -v "+00:00$" \| wc -l` → 0 ; `git log --all --format=%cI \| grep -v "+00:00$" \| wc -l` → 0 | auteur et validateur en UTC sur tout l’historique |
| REQ-ANON-009 | MEDIUM | FAIL | pages d’erreur sans chemin : `socle/src/http.js:171` ; erreurs des voisins réduites à une cause courte (`src/sources.js:69`) ; domaine et WHOIS hors dépôt | action H13 |
| REQ-ANON-010 | MEDIUM | PASS | identité stable et unique, dates réelles (TZ=UTC, jamais antidatées) | aucune politique de contribution externe |
| REQ-CFG-001 | CRITICAL | PASS | gitleaks sur tout l’historique, toutes références comprises, relancé à chaque génération de ce fichier → aucune fuite ; `git grep` de l’annexe B.2 → valeurs d’essai fabriquées ; `-----BEGIN … PRIVATE` → 0 | détail dans l’annexe B ci-dessous |
| REQ-CFG-002 | CRITICAL | PASS | secrets jamais rendus : chaque réglage passe par `reglagePublic`, qui ne dit que si un secret est posé (`src/base.js:183`) ; les jetons des sondes ne sont montrés qu’une fois et gardés par leur empreinte (`src/api.js:263`) | aucune construction : web/ est servi tel quel ; sondage exploratoire ci-dessous (« secrets dans les réglages ») |
| REQ-CFG-003 | HIGH | FAIL | VM d’essai et production distinctes (instruction de l’exploitant) | jetons du Hub, clés d’IA et de passerelle séparés par environnement : action H6 |
| REQ-CFG-004 | HIGH | PASS | `src/config.js:15` sur `socle/src/config.js:14` : jeton du Hub de 24 caractères au moins (`src/config.js:26`), jetons dérivés à leur format exact, URL valides, bornes des appels d’IA | aucun mode de débogage ni contournement par variable |
| REQ-CFG-005 | HIGH | PASS | chaque secret, son lieu et sa rotation : section « Secrets inventory » ci-dessous ; SOCLE_CLE tournée, les secrets de VIGIE rescellés (`src/base.js:118`) ; secrets des réglages retirés sans arrêter le service (`src/cli.js:52`) | essais `test/vigie.test.js:625`, `test/vigie.test.js:644` ; runbook joué par `outils/exercice-incident.mjs` (22 vérifications le 2026-10-19) ; clés chez leurs fournisseurs : actions H5, H6 |
| REQ-CI-001 | CRITICAL | FAIL | `.github/workflows/verification.yml:48` | Actions, crochet local et protection de poussée à activer : actions H3, H4 |
| REQ-CI-002 | HIGH | FAIL | CodeQL, requêtes « security-extended » : `.github/workflows/verification.yml:111` | bloquant une fois les Actions actives et le contrôle requis : action H3 |
| REQ-CI-003 | HIGH | FAIL | aucune dépendance npm, contrôlé en CI (`.github/workflows/verification.yml:38`) ; image de base épinglée `Dockerfile:6` ; actions épinglées par commit ; mises à jour proposées, jamais appliquées seules (`.github/dependabot.yml:10`) ; crible de l’image `.github/workflows/publish.yml:52` ; SBOM `.github/workflows/publish.yml:88` | le dépôt est prêt ; l’exécution en CI, les alertes et le contrôle requis dépendent de GitHub : action H3 |
| REQ-CI-004 | HIGH | FAIL | `.github/workflows/verification.yml:85` | échoue tant que le secret n’existe pas : action H4 |
| REQ-CI-005 | MEDIUM | FAIL | permissions minimales `.github/workflows/verification.yml:15` ; actions épinglées par commit | protection de branche : action H3 |
| REQ-CI-006 | MEDIUM | PASS | `test/vigie.test.js:293` : chaque route du routeur balayée sans session (401), puis en lecture, en membre, avec le jeton du Hub et un jeton dérivé, selon une table de droits (`test/vigie.test.js:279`) ; une route absente de la table fait échouer l’essai | renforts : `test/vigie.test.js:414` ; cassures volontaires : NO-VIBE.md |
| REQ-WEB-001 | CRITICAL | FAIL | HSTS dès que la requête est chiffrée : `socle/src/http.js:88` | VIGIE est publiée par le Hub ou sur la boucle locale ; servie en HTTP tant qu’aucun relais TLS n’est posé : action H1 |
| REQ-WEB-002 | HIGH | PASS | chaque page : `src/main.js:78` sur `socle/src/http.js:62` (script-src 'self' et un nonce par requête, object-src 'none', base-uri 'none', frame-ancestors 'none', aucun unsafe-inline ni unsafe-eval) | essai `test/vigie.test.js:255` ; parcours navigateur du 2026-10-19 : 91 écrans et largeurs, aucune erreur en console |
| REQ-WEB-003 | HIGH | PASS | `socle/src/http.js:79`, Referrer-Policy, Permissions-Policy, X-Frame-Options, COOP, CORP, no-store, ni Server ni X-Powered-By (annexe B.4) | HSTS dès HTTPS (H1) |
| REQ-WEB-004 | HIGH | PASS | aucun en-tête CORS émis : `curl -sI -H "Origin: https://evil.example" /api/etat` → aucun Access-Control-* (annexe B.4) | API de même origine pour le navigateur ; le Hub appelle de serveur à serveur |
| REQ-WEB-005 | HIGH | PASS | CSRF : `socle/src/portail.js:98` ; JSON exigé : `socle/src/http.js:122` ; aucun GET n’écrit ; SSRF : les adresses saisies (billetterie, listes ajoutées) refusent lien local, métadonnées et adresses réservées à l’enregistrement et à chaque envoi après résolution (`src/destination.js:15`), sans redirection ; les voisins viennent de la configuration du Hub, jamais d’une requête | essais `test/vigie.test.js:681`, `test/vigie.test.js:190` |
| REQ-WEB-006 | CRITICAL | PASS | corps : schéma strict, champ inconnu refusé (`socle/src/schema.js:69`) ; paramètres de requête : schéma par route, tout paramètre non déclaré refusé, même quand la route rend tôt (`src/api.js:543`) ; identifiants au format exact avant toute lecture (`src/api.js:536`) ; adresses, plages et empreintes validées (`src/api.js:366`) ; lignes de journaux et événements EVE bornés (`src/bouclier/recepteur.js:10`) | essais `test/vigie.test.js:293`, `test/vigie.test.js:190` ; sondage exploratoire ci-dessous |
| REQ-WEB-007 | HIGH | PASS | requêtes préparées partout ; aucun processus lancé par le serveur (`grep -rnE "child_process\|execFile\|spawn" src` → 0) ; les voisins reçoivent du JSON sérialisé, jamais une chaîne assemblée ; `innerHTML` seulement dans le gabarit du socle, sur du balisage écrit dans le code (`socle/web/gabarit.js:115`) ; les PDF échappent chaque chaîne (`src/pdf.js:38`) | eval et Function absents ; les lignes de journaux ne sont jamais exécutées, seulement lues par des expressions ancrées et bornées (`test/sentinelle.test.js:87`) |
| REQ-WEB-008 | MEDIUM | PASS | débit global par adresse `src/main.js:70` ; syslog : 3 000 lignes par seconde comptées après le filtre des émetteurs (`src/bouclier/recepteur.js:11`), 32 connexions TCP ; trente-deux flux en direct (`src/sentinelle/index.js:13`) ; réponses des voisins, des IA, de Cloudflare et des listes lues jusqu’à une taille permise (`src/lecture.js:10`) ; un audit à la fois ; IA plafonnée par jour (`src/ia.js:147`) ; adresses du bouclier bornées à cinquante mille (`src/bouclier/correlation.js:20`) | essais `test/bouclier.test.js:403`, `test/vigie.test.js:176` |
| REQ-DATA-001 | CRITICAL | PASS | SQLite embarqué, aucun port : `src/base.js:30` ; dossier en 0700 et base en 0600 : `src/base.js:28` | essai `test/vigie.test.js:255` |
| REQ-DATA-002 | HIGH | FAIL | secrets des réglages et TOTP scellés AES-256-GCM, sous-clé par usage (`src/base.js:105` sur `socle/src/chiffre.js:60`) ; passerelle UniFi en TLS épinglé (`src/bouclier/tls.js:38`) ; IA en nuage, Telegram et Cloudflare en HTTPS vérifié | restent le chiffrement du disque des hôtes, HTTPS vers VIGIE elle-même et le trafic entre conteneurs du Hub : actions H7, H1 |
| REQ-DATA-003 | HIGH | FAIL | sauvegarde chiffrée pour une clé publique RSA : `src/cli.js:65` ; restauration ailleurs avec la clé privée seule : `src/cli.js:23` ; restauration réelle puis démarrage sur la base restaurée : `outils/exercice-incident.mjs:79` (2026-10-19, instance d’essai) | essai `test/vigie.test.js:644` ; planification quotidienne, copie hors hôte, trente jours de garde et restauration datée : action H8 |
| REQ-DATA-004 | HIGH | PASS | socle : connexions, facteurs, rôles, refus (`socle/src/portail.js:110`), verrous du limiteur ; VIGIE : jetons refusés (`src/api.js:123`), gestes hors portée d’un jeton ou d’un rôle (`src/api.js:128`), audits lancés, isolements et annulations, blocages et levées, réglages changés, sondes, listes, sauvegardes et secrets retirés ; jamais un secret : `socle/src/journal.js:10` | essai `test/vigie.test.js:705` |
| REQ-DATA-005 | MEDIUM | PASS | vigie : `socle/src/vigie.js:11` (connexions, refus, limites, erreurs internes), jetons refusés compris ; runbook d’une page ci-dessous, joué de bout en bout sur une instance lancée comme en production le 2026-10-19 (`outils/exercice-incident.mjs`, 22 vérifications) : détection au journal, sessions fermées en une requête, jeton du Hub changé, secrets retirés, mot de passe forcé, restauration | rotation de SOCLE_CLE : essai `test/vigie.test.js:625` ; alertes hors de l’application par courriel : action H2 |
| REQ-DATA-006 | MEDIUM | PASS | `web/confidentialite.txt:7` (chaque donnée, sa finalité, sa durée) ; audits bornés à deux cents, événements à cinq mille, actions à un an (`src/base.js:23`), alertes de la sentinelle à la rétention réglée, blocages à 180 jours après leur fin ; export et effacement : `src/main.js:64` | essais `test/vigie.test.js:611`, `test/vigie.test.js:699` |
| REQ-DATA-007 | MEDIUM | N/A | aucun envoi de fichier ni import depuis une adresse fournie par un utilisateur : corps JSON seulement (`socle/src/http.js:122`), `grep -rniwE "multipart\|busboy\|formidable" src socle/src` → 0 ; les listes de menaces ajoutées sont lues comme du texte, bornées, jamais exécutées (voir SEC-CSRF-004) |  |
| REQ-CODE-001 | HIGH | PASS | essais de référence relevés avant la passe (voir NO-VIBE.md) ; surface publique inchangée : mêmes routes, mêmes schémas, mêmes codes ; seuls changements de comportement voulus, chacun un correctif : réglages qui rendent VIGIE sourde sous renfort, journaux d’un émetteur non déclaré signalés au lieu d’agir, adresses interdites refusées | voir NO-VIBE.md |
| REQ-CODE-002 | HIGH | PASS | voir NO-VIBE.md, couche des commentaires |  |
| REQ-CODE-003 | HIGH | PASS | voir NO-VIBE.md, couches structurelle et défensive |  |
| REQ-CODE-004 | HIGH | PASS | voir NO-VIBE.md, profil de style du dépôt |  |
| REQ-CODE-005 | MEDIUM | PASS | cassures volontaires, chacune détectée par au moins un essai : NO-VIBE.md, « Tests » |  |
| REQ-CODE-006 | MEDIUM | PASS | un sujet par commit, message d’une seule ligne dans le style du dépôt : `git log --format=%b \| grep -c .` → 0 (aucun corps, aucune ligne de fin) ; `git log --format=%B \| grep -ciE "co-authored\|generated\|claude\|anthropic\|assistant"` → 0 ; le socle embarqué vérifié par ses empreintes (`socle/EMPREINTES:14`) | en UTC : `git log --format=%cI \| grep -v "+00:00$" \| wc -l` → 0 ; relevés commités seuls, jamais mêlés à un changement |
| GOV-001 | HIGH | PASS | ce document : revue datée, périmètre (258 contrôles), résolution ligne par ligne, deux passes complètes | à refaire à chaque changement généré important |
| GOV-002 | MEDIUM | PASS | section « Inventory » ci-dessous : routes, données, tiers, secrets |  |
| GOV-003 | LOW | FAIL | `socle/src/portail.js:150` ; contact : `src/main.js:24` | essai `test/vigie.test.js:255` (Contact et Expires) ; activer le signalement privé sur le dépôt : action H3 |
| GOV-004 | MEDIUM | FAIL | VM d’essai distincte de la production (règle de l’exploitant) ; données d’essai fabriquées, faux voisins pour les essais et la vitrine (`outils/vitrine.mjs:1`) | jetons et clés distincts à confirmer : action H6 |
| GOV-005 | HIGH | FAIL | jeton CI éphémère et limité : `.github/workflows/publish.yml:26` | 2FA sur GitHub et consoles des fournisseurs : action H3 |
| SEC-SECRETS-001 | CRITICAL | PASS | gitleaks sur tout l’historique → aucune fuite ; `git grep` de REQ-CFG-001 → valeurs d’essai seulement | gitleaks en CI (H3) |
| SEC-SECRETS-002 | CRITICAL | PASS | aucune variable publique ni construction : web/ servi tel quel, `grep -rnE "\bsk-[A-Za-z0-9_-]{20}\|sk_live\|service_role\|-----BEGIN" web socle/web` → 0 | rien n’est injecté dans le code servi, sauf le nonce CSP et la gamme : `web/index.html:11` |
| SEC-SECRETS-003 | CRITICAL | PASS | `.gitignore:9` ; seuls web/ et socle/web sont servis, tout segment caché → 404 (annexe B.2, `/.env` demandé à l’instance d’essai) | secrets d’une installation seule : `secrets/`, ignoré (`.gitignore:8`) |
| SEC-SECRETS-004 | HIGH | PASS | installé par le Hub : secrets posés depuis son coffre (`deploy/compose.hub.yml:59`) ; installé seul : secret Docker hors du volume (`docker-compose.yml:20`) ; fichiers acceptés : `socle/src/config.js:5` ; clés d’IA, Telegram, UniFi et Cloudflare saisies dans l’interface et scellées en base | jamais dans la CI |
| SEC-SECRETS-005 | HIGH | FAIL | une clé par usage, lue par VIGIE seule ; jeton dérivé par source, qui ne vaut que pour elle (`src/config.js:13`) | clés UniFi et Cloudflare restreintes, séparées par environnement : action H6 |
| SEC-SECRETS-006 | HIGH | FAIL | procédures de rotation ci-dessous ; SOCLE_CLE exercée (`test/vigie.test.js:625`) | clés et jetons vus pendant le développement : action H5 |
| SEC-SECRETS-007 | HIGH | PASS | clé maîtresse de 32 octets aléatoires : `socle/src/chiffre.js:24` ; jeton du Hub de 24 caractères au moins (`src/config.js:26`) ; valeurs d’exemple refusées : `socle/src/config.js:54` | jetons de sonde et de liste tirés par le serveur (voir REQ-CRYPT-005) |
| SEC-SECRETS-008 | MEDIUM | PASS | `src/config.js:15` : une valeur invalide arrête le démarrage avec la liste des erreurs ; aucun mode de débogage ; mode HTTP dégradé affiché en permanence : `socle/web/compte.js:589`, `socle/web/compte.js:769` |  |
| SEC-AUTH-001 | CRITICAL | PASS | voir REQ-CRYPT-001 |  |
| SEC-AUTH-002 | MEDIUM | PASS | voir REQ-CRYPT-004 |  |
| SEC-AUTH-003 | CRITICAL | PASS | voir REQ-AUTH-010 : humains par adresse et par compte, jeton du Hub par adresse, dans le même limiteur persistant |  |
| SEC-AUTH-004 | MEDIUM | PASS | voir REQ-AUTH-011 |  |
| SEC-AUTH-005 | CRITICAL | PASS | voir REQ-AUTH-006 ; lien depuis l’adresse publique : `socle/src/portail.js:56` | sans adresse publique, l’origine attestée par le navigateur de l’administrateur, contrôlée sur la même requête |
| SEC-AUTH-006 | MEDIUM | PASS | confirmation sur la nouvelle adresse et avis à l’ancienne : `socle/src/comptes.js:1047` | essai `socle/test/courriel.test.js:122` |
| SEC-AUTH-007 | HIGH | PASS | TOTP et clés pour tous, second facteur imposé aux administrateurs : `socle/src/comptes.js:178` | codes de secours toujours émis |
| SEC-AUTH-008 | HIGH | N/A | aucune connexion par fournisseur externe : `grep -rniwE "oauth\|openid\|id_token\|redirect_uri" socle/src src` → 0 |  |
| SEC-AUTH-009 | HIGH | PASS | les liens reçus par courriel demandent un geste : `socle/web/compte.js:452` ; uniques et courts : `socle/src/comptes.js:38` | aucune connexion sans mot de passe par courriel |
| SEC-AUTH-010 | CRITICAL | PASS | chaque route non publique appelle `acces()`, `admin()` ou `session()` en tête, avant de lire son corps : `src/api.js:130` ; les routes publiques vérifient leur propre jeton (sonde, liste) | essai `test/vigie.test.js:293` |
| SEC-AUTH-011 | HIGH | PASS | jeton faux → 401 : `src/api.js:124` ; erreur imprévue réduite à un numéro : `socle/src/http.js:171` | un jeton présenté ne retombe jamais sur la session (sondage exploratoire ci-dessous) |
| SEC-SESS-001 | CRITICAL | PASS | voir REQ-SESS-001 |  |
| SEC-SESS-002 | HIGH | PASS | `grep -rn "localStorage" web socle/web/compte.js` → thème seulement (`socle/web/compte.js:302`), jamais une session |  |
| SEC-SESS-003 | HIGH | PASS | 256 bits : `socle/src/comptes.js:289` | renouvelé à chaque changement de niveau |
| SEC-SESS-004 | HIGH | PASS | voir REQ-SESS-003, REQ-SESS-004 et REQ-SESS-006 |  |
| SEC-SESS-005 | CRITICAL | N/A | aucun JWT : `grep -rniwE "jwt\|jsonwebtoken\|jose" src web socle/src` → 0 |  |
| SEC-SESS-006 | MEDIUM | N/A | aucun jeton de rafraîchissement : sessions serveur (voir SEC-SESS-005) |  |
| SEC-SESS-007 | MEDIUM | PASS | voir REQ-SESS-005 ; avis par courriel via le canal d’alerte | courriel : H2 |
| SEC-AUTHZ-001 | CRITICAL | PASS | le réseau audité est partagé entre les opérateurs, sans propriétaire d’objet : la portée est le rôle ; chaque appareil désigné est relu chez MapMyLAN et borné au périmètre déclaré avant toute action (`src/veille.js:229`) | essai `test/vigie.test.js:462` |
| SEC-AUTHZ-002 | CRITICAL | PASS | rôle humain lu en base par le socle (`socle/src/portail.js:120`) ; portée des jetons fermée : dérivé = lecture et audit, Hub = lecture, audits et actions, jamais les réglages (`src/api.js:130`) ; isoler réservé à l’administrateur, forcer une isolation sous renfort et jamais par un jeton | essais `test/vigie.test.js:293`, `test/vigie.test.js:414` |
| SEC-AUTHZ-003 | HIGH | PASS | schémas stricts, champ inconnu refusé : `socle/src/schema.js:69` ; l’auteur d’un geste vient de la session ou du jeton, jamais du corps (`src/api.js:141`) | sondage exploratoire ci-dessous (« champ inconnu », « prototype pollué ») |
| SEC-AUTHZ-004 | HIGH | PASS | route /api inconnue → 404, méthode inconnue → 405 avec Allow : `src/api.js:534` ; trois routes publiques : santé, envoi d’une sonde (son jeton), liste des pare-feu (son jeton) | aucune route de débogage ni de semis ; table des droits : `test/vigie.test.js:279` |
| SEC-AUTHZ-005 | CRITICAL | N/A | aucune notion de locataire : une instance surveille un réseau ; `grep -rniwE "tenants?\|organisations?\|workspaces?" src` → 0 |  |
| SEC-AUTHZ-006 | LOW | PASS | références aléatoires de 72 bits pour les audits, constats, événements, actions et blocages (`src/base.js:11`), validées au format exact avant toute lecture |  |
| SEC-AUTHZ-007 | HIGH | PASS | invariants tenus par le serveur : jamais une adresse privée ni de la liste blanche bloquée (`src/bouclier/riposte.js:68`) ; plafond horaire de blocages et d’isolements ; jamais l’infrastructure isolée seule (`src/veille.js:210`) ; jamais hors du périmètre ; rien d’automatique sur la foi de journaux non vérifiés (`src/bouclier/riposte.js:93`) ; un constat critique jamais écarté par l’IA | essais `test/bouclier.test.js:228`, `test/bouclier.test.js:259`, `test/vigie.test.js:672` |
| SEC-AUTHZ-008 | MEDIUM | PASS | rôle et renfort exigés par le serveur, jamais par l’interface : chaque route est refusée appelée directement | essai `test/vigie.test.js:293` |
| SEC-INJ-001 | CRITICAL | PASS | requêtes préparées partout ; aucun texte SQL assemblé à partir d’une valeur (`grep -rnE "prepare\(\`[^\`]*\$\{" src` : seuls les noms de tables et de colonnes du déclencheur d’oubli, écrits dans le code, `src/base.js:155`) | annexe B.3 : aucune interpolation de valeur dans le texte SQL |
| SEC-INJ-002 | HIGH | N/A | aucun ORM : node:sqlite, requêtes préparées seulement |  |
| SEC-INJ-003 | HIGH | N/A | aucune base documentaire : SQLite seulement ; JSON rangé en colonne texte |  |
| SEC-INJ-004 | CRITICAL | PASS | aucun processus lancé (`grep -rnE "child_process\|execFile\|spawn" src` → 0) ; les lignes de journaux reçues sont lues par des expressions régulières, jamais interprétées ; les actions sur le réseau passent par l’API de MapMyLAN, par identifiant d’appareil encodé (`src/sources.js:195`) |  |
| SEC-INJ-005 | HIGH | PASS | `socle/src/http.js:205` ; listes de menaces écrites sous un nom tiré de leur identifiant, jamais d’une saisie (`src/bouclier/menaces.js:75`) |  |
| SEC-INJ-006 | HIGH | PASS | aucun gabarit côté serveur ; `grep -rnE "new Function\|node:vm" src socle/src` → 0 | l’interface construit son DOM en texte (voir SEC-XSS-001) |
| SEC-INJ-007 | HIGH | N/A | aucun analyseur XML côté serveur : `grep -rniwE "xml2js\|sax\|libxml\|fast-xml\|DOMParser" src socle/src` → 0 (le navigateur ne lit en SVG que les pictogrammes et le QR code qu’il dessine lui-même) |  |
| SEC-INJ-008 | HIGH | PASS | JSON seulement ; clés de prototype refusées : `socle/src/schema.js:6` ; EVE des sondes lu champ par champ, profondeur bornée (`src/api.js:65`) ; réponses des voisins relues champ par champ et bornées |  |
| SEC-XSS-001 | CRITICAL | PASS | interface : DOM construit par `h()` du socle, texte seulement (`socle/web/compte.js:11`) ; graphiques construits nœud par nœud (`socle/web/graphes.js:3`) ; sortie de l’IA filtrée (liens et balises retirés, `src/ia.js:32`) puis posée en texte | noms d’appareils, bannières, lignes de journaux et synthèses de l’IA affichés en texte brut |
| SEC-XSS-002 | HIGH | N/A | aucun texte riche ni Markdown rendu : synthèses de l’IA, constats et lignes de journaux affichés en texte brut (voir SEC-XSS-001) |  |
| SEC-XSS-003 | HIGH | PASS | aucun eval, setTimeout chaîne ni affectation de location depuis une donnée : `grep -rnE "eval\(\|new Function\|location\.href *=" web socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-XSS-004 | HIGH | PASS | voir REQ-WEB-002 |  |
| SEC-XSS-005 | MEDIUM | PASS | seul échange : le Worker de preuve de travail, de même origine : `socle/web/compte.js:236` | aucune écoute de window message |
| SEC-XSS-006 | MEDIUM | PASS | une erreur d’un voisin : la cause courte, bornée (`src/sources.js:69`) ; erreurs imprévues réduites à un numéro (`socle/src/http.js:171`) |  |
| SEC-XSS-007 | MEDIUM | N/A | aucune redirection pilotée par paramètre ; `curl -sI "/login?next=https://evil.example"` → aucun Location (annexe B.4) |  |
| SEC-XSS-008 | MEDIUM | PASS | aucun script tiers ni CDN : tout est servi par VIGIE (`grep -rnE "https?://" web/index.html` → 0) | polices servies par le socle |
| SEC-HDR-001 | HIGH | FAIL | voir REQ-WEB-001 | action H1 |
| SEC-HDR-002 | HIGH | PASS | voir REQ-WEB-002 |  |
| SEC-HDR-003 | MEDIUM | PASS | voir REQ-WEB-003 |  |
| SEC-HDR-004 | LOW | PASS | `curl -sI /` : ni Server ni X-Powered-By (annexe B.4) |  |
| SEC-HDR-005 | MEDIUM | PASS | no-store sur l’API et les pages : `socle/src/http.js:150` ; seuls les fichiers publics de l’interface, sous leur version (`/v/<version>/`), sont mis en cache (`src/main.js:85`) | aucun CDN |
| SEC-HDR-006 | CRITICAL | PASS | voir REQ-WEB-004 |  |
| SEC-HDR-007 | HIGH | PASS | voir REQ-SESS-001 |  |
| SEC-CSRF-001 | HIGH | PASS | SameSite=Strict + origine + jeton : `socle/src/portail.js:98` appelé par chaque écriture de session | sondage exploratoire ci-dessous (« écriture sans jeton anti-CSRF », « depuis une autre origine ») ; le Hub et les sondes présentent un jeton en en-tête, que le navigateur n’envoie jamais seul |
| SEC-CSRF-002 | MEDIUM | PASS | `socle/src/http.js:122` | 415 sur tout autre type |
| SEC-CSRF-003 | MEDIUM | PASS | voir REQ-WEB-005 : aucun GET n’écrit | les GET de VIGIE lisent sa base ; la liste des pare-feu ne fait que lire |
| SEC-CSRF-004 | CRITICAL | PASS | adresses que le serveur joint : les voisins, posés par le Hub ; la billetterie et les listes ajoutées, par un administrateur sous renfort, refusées vers le lien local, les métadonnées d’un nuage et les adresses réservées, en littéral à l’enregistrement (`src/api.js:98`) et après résolution à chaque envoi (`src/destination.js:15`) ; aucune redirection suivie ; les sondes TLS n’envoient aucune donnée applicative (`src/bouclier/tls.js:22`, `src/sources.js:231`) | essai `test/vigie.test.js:681` ; la billetterie vit sur le réseau interne par nature : le réseau privé et la machine elle-même y restent permis |
| SEC-CSRF-005 | HIGH | PASS | webhooks sortants : billetterie (clé d’en-tête, clé d’idempotence, sans redirection, `src/diffusion.js:46`) et Telegram (envoi seul, aucun bot qui écoute) ; données reçues : seulement les sondes, authentifiées par leur jeton | essai `test/vigie.test.js:513` |
| SEC-CSRF-006 | MEDIUM | N/A | aucune redirection pilotée par paramètre : voir SEC-XSS-007 |  |
| SEC-API-001 | HIGH | PASS | voir REQ-WEB-006 |  |
| SEC-API-002 | HIGH | PASS | voir REQ-WEB-008 ; échecs du jeton du Hub plafonnés par adresse (voir REQ-AUTH-010) |  |
| SEC-API-003 | MEDIUM | PASS | audits par 200 au plus, événements par 500, alertes de la sentinelle par 1 000 (`src/api.js:69`) ; aucun paramètre de taille non déclaré accepté |  |
| SEC-API-004 | HIGH | PASS | réponses construites champ par champ : état (`src/api.js:145`), réglages publics sans secret, sondes sans empreinte | sondage exploratoire ci-dessous |
| SEC-API-005 | MEDIUM | PASS | 405 avec Allow : `src/api.js:535` ; aucune page de documentation ni de débogage |  |
| SEC-API-006 | HIGH | N/A | aucun GraphQL : `grep -rniwE "graphql\|apollo" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-API-007 | MEDIUM | PASS | un seul formateur d’erreurs : `socle/src/http.js:159` ; erreur d’un voisin rendue en 502 avec un message écrit pour l’opérateur ; rescellage des secrets après une rotation en une seule transaction (`src/base.js:121`) |  |
| SEC-API-008 | MEDIUM | N/A | aucune opération monétaire ni crédit : `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; le plafond d’appels d’IA est un garde-fou de coût, compté localement (voir SEC-LLM-002) |  |
| SEC-API-009 | HIGH | PASS | pas de RPC implicite ; le flux en direct est en lecture seule (SSE) ; l’envoi d’une sonde n’accepte qu’une liste d’événements EVE bornée |  |
| SEC-API-010 | MEDIUM | PASS | `socle/src/http.js:128` ; 32 Kio par défaut (`src/api.js:140`), 4 Mio pour une sonde ; lignes de journaux à 16 Kio | sondage exploratoire ci-dessous (« corps géant ») |
| SEC-DB-001 | CRITICAL | PASS | voir REQ-DATA-001 |  |
| SEC-DB-002 | HIGH | N/A | SQLite embarqué sans rôle ni identifiant : `src/base.js:30` |  |
| SEC-DB-003 | HIGH | FAIL | aucun trafic réseau vers la base ; secrets de facteurs et des réglages chiffrés | chiffrement du disque des hôtes : action H7 |
| SEC-DB-004 | MEDIUM | PASS | secrets TOTP et des réglages scellés AES-256-GCM, sous-clé par usage (`src/base.js:105`) ; clé maîtresse jamais dans le volume : secret du Hub, ou secret Docker hors du volume pour l’installation seule (`docker-compose.yml:20`), secret vide refusé au démarrage | essai `test/vigie.test.js:644` (base restaurée lue en brut : secrets toujours scellés) |
| SEC-DB-005 | CRITICAL | PASS | voir SEC-INJ-001 |  |
| SEC-DB-006 | HIGH | FAIL | voir REQ-DATA-003 | action H8 |
| SEC-DB-007 | MEDIUM | PASS | essais sur données fabriquées ; aucun compte par défaut : jeton d’installation exigé (`socle/src/comptes.js:249`) |  |
| SEC-DB-008 | CRITICAL | N/A | le navigateur ne parle jamais à la base : SQLite côté serveur seulement |  |
| SEC-DB-009 | LOW | PASS | `src/base.js:31` ; listes plafonnées | un seul processus, pas de pool nécessaire |
| SEC-DB-010 | LOW | PASS | voir REQ-DATA-004 : isolements, blocages, réglages, sauvegardes et secrets retirés au journal chaîné |  |
| SEC-FILE-001 | HIGH | N/A | aucun envoi de fichier : corps JSON seulement (`socle/src/http.js:122`) |  |
| SEC-FILE-002 | MEDIUM | N/A | aucun envoi de fichier ; corps JSON bornés (voir SEC-API-010) |  |
| SEC-FILE-003 | HIGH | N/A | aucun fichier d’utilisateur écrit ; seules écritures : la base et les listes de menaces, nommées par le serveur (`src/bouclier/menaces.js:75`) |  |
| SEC-FILE-004 | HIGH | N/A | aucun fichier d’utilisateur servi ; le rapport PDF est produit par le serveur, en pièce jointe (`src/api.js:186`) |  |
| SEC-FILE-005 | CRITICAL | N/A | aucun fichier d’utilisateur stocké |  |
| SEC-FILE-006 | MEDIUM | N/A | aucun fichier partagé entre utilisateurs |  |
| SEC-FILE-007 | LOW | N/A | aucune image acceptée |  |
| SEC-FILE-008 | HIGH | N/A | aucun import par adresse fournie par un utilisateur, hors des listes de menaces ajoutées par un administrateur sous renfort : voir SEC-CSRF-004 |  |
| SEC-PAY-001 | CRITICAL | N/A | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement |  |
| SEC-PAY-002 | CRITICAL | N/A | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement ; aucun webhook de paiement reçu |  |
| SEC-PAY-003 | HIGH | N/A | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement ; aucun abonnement |  |
| SEC-PAY-004 | HIGH | N/A | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement |  |
| SEC-PAY-005 | HIGH | N/A | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement |  |
| SEC-PAY-006 | HIGH | PASS | vérification : 5 par heure par compte et par adresse (`socle/src/portail.js:38`) ; alertes : 30 par heure et par compte (`socle/src/notifications.js:98`) | destinataires et contenus jamais choisis par une requête |
| SEC-PAY-007 | MEDIUM | FAIL | le domaine d’expédition est celui du relais de l’exploitant | SPF, DKIM et DMARC à publier avec le relais : action H2 |
| SEC-PAY-008 | MEDIUM | PASS | aucun mot de passe dans un courriel ; liens uniques, hachés, de 30 minutes (`socle/src/comptes.js:38`) ou 72 heures pour fermer les sessions (`socle/src/notifications.js:27`) | le lien de révocation ne peut que fermer des sessions |
| SEC-NEXT-001 | CRITICAL | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-002 | CRITICAL | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-003 | HIGH | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-004 | CRITICAL | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-005 | HIGH | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-006 | HIGH | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-007 | HIGH | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-008 | MEDIUM | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-NEXT-009 | MEDIUM | N/A | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-BAAS-001 | CRITICAL | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-002 | CRITICAL | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-003 | CRITICAL | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-004 | HIGH | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-005 | CRITICAL | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-006 | HIGH | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-007 | MEDIUM | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-008 | CRITICAL | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-009 | CRITICAL | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-010 | HIGH | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BAAS-011 | HIGH | N/A | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |  |
| SEC-BE-001 | MEDIUM | PASS | en-têtes posés avant toute route, erreurs et 429 compris : `src/main.js:78` | annexe B.4 ; essai `test/vigie.test.js:255` |
| SEC-BE-002 | MEDIUM | PASS | corps bornés ; 404 pour l’inconnu ; relais de confiance explicites : `socle/src/http.js:14` ; délais du serveur : `src/main.js:92` ; délais et taille des réponses des voisins bornés (`src/sources.js:58`) | formateur d’erreurs unique : `src/main.js:90` |
| SEC-BE-003 | HIGH | PASS | voir SEC-INJ-004 et SEC-INJ-008 ; aucun import dynamique d’un chemin fourni | modules du navigateur importés depuis des chemins fixes, relatifs à la version servie |
| SEC-BE-004 | HIGH | PASS | aucune dépendance npm, contrôlé en CI (`.github/workflows/verification.yml:38`) : rien à verrouiller | Playwright ne sert qu’à l’outil de parcours, hors de l’image et du dépôt |
| SEC-BE-005 | CRITICAL | N/A | aucun Django : serveur Node seul |  |
| SEC-BE-006 | HIGH | N/A | aucun Flask ni FastAPI : serveur Node seul, aucun Python dans le dépôt (`git ls-files "*.py" \| wc -l` → 0) |  |
| SEC-BE-007 | HIGH | N/A | aucun Python dans le dépôt : voir SEC-BE-006 |  |
| SEC-BE-008 | HIGH | N/A | aucun PHP : `git ls-files "*.php" \| wc -l` → 0 |  |
| SEC-BE-009 | MEDIUM | PASS | `Dockerfile:18` ; aucun programme setuid ni setgid dans l’image ; base alpine épinglée ; dossier de données en 0700, base et fichiers WAL en 0600 : `src/base.js:29` |  |
| SEC-BE-010 | MEDIUM | PASS | `socle/src/http.js:159` ; sonde publique réduite à « vivant » : `src/api.js:160` | essai `test/vigie.test.js:255` |
| SEC-WP-001 | CRITICAL | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-WP-002 | HIGH | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-WP-003 | HIGH | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-WP-004 | MEDIUM | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-WP-005 | MEDIUM | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-WP-006 | CRITICAL | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-WP-007 | HIGH | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-WP-008 | MEDIUM | N/A | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |
| SEC-INFRA-001 | HIGH | FAIL | voir REQ-WEB-001 | action H1 |
| SEC-INFRA-002 | MEDIUM | FAIL | aucun domaine dans le dépôt | DNS, CAA et verrou du registraire du domaine éventuel : action H13 |
| SEC-INFRA-003 | HIGH | FAIL | hôtes de l’exploitant | pare-feu, SSH par clé, mises à jour, port syslog ouvert au seul réseau de la passerelle : action H9 |
| SEC-INFRA-004 | MEDIUM | FAIL | `Dockerfile:6` ; `Dockerfile:18` ; `deploy/compose.hub.yml:18` ; `deploy/compose.hub.yml:21` ; `deploy/compose.hub.yml:23` ; installé seul : interface publiée sur la boucle locale (`docker-compose.yml:15`) | crible de l’image (Grype en CI, Trivy au déploiement) à exécuter : actions H3, H14 |
| SEC-INFRA-005 | CRITICAL | N/A | aucun stockage objet : `grep -rniwE "s3\.\|gcs\|azure\|bucket" src socle/src` → 0 (le seul « aws » du code est un motif de détection d’URL hostile de la sentinelle) |  |
| SEC-INFRA-006 | HIGH | N/A | aucun nuage : service auto-hébergé, aucune clé IAM |  |
| SEC-INFRA-007 | HIGH | FAIL | permissions minimales, actions épinglées par commit, aucun secret pour les demandes de fusion | protection de branche et revue requise : action H3 |
| SEC-INFRA-008 | MEDIUM | FAIL | empreinte d’image, provenance et SBOM à la publication : `.github/workflows/publish.yml:87` | la publication tourne sur les Actions : action H3 |
| SEC-INFRA-009 | MEDIUM | N/A | aucune infrastructure décrite en code : `find . -name "*.tf" -o -name "Pulumi.yaml"` → 0 fichier |  |
| SEC-DEP-001 | HIGH | PASS | aucune dépendance npm ; image de base par empreinte (`Dockerfile:6`) ; actions par commit |  |
| SEC-DEP-002 | HIGH | FAIL | aucune dépendance npm ; image passée au crible à chaque publication (`.github/workflows/publish.yml:52`) | alertes Dependabot et contrôle requis : action H3 |
| SEC-DEP-003 | MEDIUM | PASS | aucune dépendance npm ni bibliothèque du navigateur : graphiques, gabarit et PDF écrits ici (`src/pdf.js:172`) |  |
| SEC-DEP-004 | MEDIUM | PASS | actions épinglées par commit (`.github/workflows/verification.yml:22`) ; image par empreinte ; mises à jour proposées en demandes de fusion, jamais fusionnées seules (`.github/dependabot.yml:6`) | revue requise avant fusion : protection de branche, action H3 |
| SEC-DEP-005 | MEDIUM | PASS | aucune installation de paquet npm : ni npm install ni script de cycle de vie, dans le dépôt comme dans l’image (`Dockerfile:14` sans installation) |  |
| SEC-DEP-006 | LOW | FAIL | `.github/workflows/publish.yml:88` | produit par la publication (H3) |
| SEC-DEP-007 | MEDIUM | PASS | voir SEC-XSS-008 |  |
| SEC-DEP-008 | LOW | FAIL | crible de l’image à chaque publication | abonnement aux avis GitHub : action H3 |
| SEC-LLM-001 | CRITICAL | PASS | clé du fournisseur scellée en base, jamais rendue (`src/base.js:105`, réglages publics) ; seul le serveur appelle le fournisseur (`src/ia.js:177`) ; `grep -rnE "sk-[A-Za-z0-9_-]{10,}" web socle/web` → 0 | posée sous renfort ; un changement de fournisseur aussi (la clé partirait ailleurs) |
| SEC-LLM-002 | CRITICAL | FAIL | aucun point d’accès d’IA ouvert : la relecture n’est déclenchée que par un audit, lancé par un membre, le Hub ou un jeton dérivé, un à la fois ; plafond quotidien d’appels et de jetons compté avant l’appel (`src/ia.js:147`) ; `max_tokens` borne chaque appel (`src/ia.js:187`) | plafond de dépense chez le fournisseur : action H18 ; essai `test/vigie.test.js:358` |
| SEC-LLM-003 | HIGH | PASS | données venues du réseau balisées DONNEES/MEMOIRE/RELECTURE et déclarées données dans la consigne (`src/ia.js:39`), champs bornés et nettoyés (`src/ia.js:26`) ; réponse relue champ par champ (`src/ia.js:103`) : l’IA ne change ni gravité, ni score, ni ne déclenche d’action ; un constat critique n’est jamais écarté | essais `test/vigie.test.js:142`, `test/vigie.test.js:151` |
| SEC-LLM-004 | HIGH | PASS | sortie filtrée : caractères de contrôle, liens et balises retirés, longueur bornée (`src/ia.js:32`) ; posée en texte dans l’interface et le PDF ; jamais exécutée ni utilisée en SQL ou en chemin |  |
| SEC-LLM-005 | CRITICAL | N/A | aucun outil ni agent : le modèle reçoit des constats et rend du JSON relu champ par champ, sans appel de fonction (`grep -rniE "tool_choice\|function_call\|tool_use" src` → 0) ; aucune action ne dépend de sa réponse (voir SEC-LLM-003) |  |
| SEC-LLM-006 | HIGH | PASS | aucun secret ni compte dans le contexte : seuls les constats (appareil, preuve, correction) partent, bornés (`src/ia.js:68`) ; la synthèse de l’IA ne retourne pas en mémoire (`src/memoire.js:68`) ; mode « locale » : rien ne sort du réseau ; le mode nuage est un choix d’administrateur, sous renfort, écrit dans la notice de confidentialité | réglage « sans entraînement » chez le fournisseur : action H18 |
| SEC-LLM-007 | MEDIUM | N/A | aucune IA ouverte au public ni à la saisie libre : aucune route ne prend un texte pour le modèle ; seule la relecture d’un audit l’appelle, avec une consigne fixe (voir SEC-LLM-002, SEC-LLM-003) |  |
| SEC-LLM-008 | LOW | PASS | modèle choisi explicitement, jamais un alias par défaut (`src/api.js:38`) ; fournisseurs connus (`src/ia.js:17`) ; aucune base vectorielle |  |
| SEC-LOG-001 | MEDIUM | PASS | voir REQ-DATA-004 ; chaque ligne : date, acteur, adresse, action, objet, résultat (`socle/src/journal.js:10`) ; identifiant de requête : `socle/src/requete.js:12` | magasin persistant : le journal chaîné en base ; hors hôte : action H11 |
| SEC-LOG-002 | HIGH | PASS | `socle/src/journal.js:10` ; jamais un jeton, une clé ni une ligne de journal brute au journal de sécurité ; les réglages journalisés disent si un secret a changé, jamais lequel (`src/api.js:285`) |  |
| SEC-LOG-003 | MEDIUM | FAIL | sortie standard conservée par Docker, hors de portée du service : `deploy/compose.hub.yml:29`, `docker-compose.yml:36` | collecteur central hors hôte : action H11 |
| SEC-LOG-004 | MEDIUM | FAIL | règles : rafales d’échecs de connexion, jetons refusés compris, refus d’accès, verrous et limites, erreurs internes, connexion d’un administrateur (`socle/src/vigie.js:11`) ; alerte tirée de bout en bout jusqu’à la page Sécurité des administrateurs (`socle/test/surveillance.test.js:59`) | alertes hors de l’application par courriel ou Telegram : actions H2 |
| SEC-LOG-005 | LOW | FAIL | santé du conteneur : `Dockerfile:22` ; sondes du Hub (`hub.json:1237`) | surveillance externe : action H10 |
| SEC-LOG-006 | MEDIUM | PASS | runbook ci-dessous |  |
| SEC-LOG-007 | HIGH | PASS | sessions : fermeture globale `socle/src/portail.js:489` ; secrets des réglages retirés en ligne de commande, service en marche (`src/cli.js:52`) ; jeton du Hub changé au redéploiement ; SOCLE_CLE tournée sans réinscription ; chaque procédure écrite dans le runbook ci-dessous | joué de bout en bout le 2026-10-19 : `outils/exercice-incident.mjs` (22 vérifications) |
| SEC-PRIV-001 | MEDIUM | PASS | `web/confidentialite.txt:7` avec durées ; purges automatiques : `src/base.js:316`, `src/bouclier/riposte.js:155`, `socle/src/comptes.js:1062` |  |
| SEC-PRIV-002 | MEDIUM | PASS | un cookie de session indispensable, documenté ; aucun traceur (`web/confidentialite.txt:93`) |  |
| SEC-PRIV-003 | MEDIUM | PASS | `web/confidentialite.txt:72` nomme chaque destinataire, dont le fournisseur d’IA en nuage et ce qu’il reçoit ; lien depuis la page Sécurité (`web/app.js:64`) |  |
| SEC-PRIV-004 | MEDIUM | PASS | export : `socle/src/portail.js:343` complété par VIGIE (`src/base.js:141`) ; effacement en libre-service sous renfort : `socle/src/comptes.js:932`, identifiant effacé des tables de VIGIE dans la même transaction (`src/base.js:155`) | essai `test/vigie.test.js:611` |
| SEC-PRIV-005 | HIGH | FAIL | voir REQ-DATA-002 | action H7 |
| SEC-PRIV-006 | LOW | FAIL | sous-traitants possibles, tous choisis par l’exploitant : fournisseur d’IA en nuage (seulement en mode nuage), Telegram, Cloudflare, relais SMTP | accord de traitement ou fournisseur européen, et réglages « sans entraînement » chez le fournisseur d’IA : actions H15, H18 |
| SEC-PRIV-007 | MEDIUM | PASS | runbook : notification sous 72 heures |  |
| SEC-PRIV-008 | LOW | PASS | `web/confidentialite.txt:118` | aucune catégorie particulière de données |
| SEC-TEST-001 | MEDIUM | FAIL | `.github/workflows/verification.yml:113` | Actions : H3 |
| SEC-TEST-002 | HIGH | FAIL | voir REQ-CI-001 | actions H3, H4 |
| SEC-TEST-003 | HIGH | FAIL | image : `.github/workflows/publish.yml:49` | actions H3, H14 |
| SEC-TEST-004 | MEDIUM | FAIL | aucun passage DAST encore | ZAP en mode « baseline » contre la VM d’essai : action H14 |
| SEC-TEST-005 | LOW | FAIL | voir REQ-WEB-001 | notation après HTTPS : action H1 |
| SEC-TEST-006 | HIGH | PASS | voir REQ-CI-006 |  |
| SEC-TEST-007 | LOW | PASS | sondage exploratoire du 2026-10-19 (32 cas), rejoué à chaque génération de ce fichier : section « Exploratory probing » ci-dessous (rôles et jetons, jetons inventés, champs et paramètres inconnus, corps géants, adresses interdites, journaux forgés, ligne hostile, renfort) | chaque trouvaille de cet audit est devenue un essai de non-régression (voir « Findings ») |
| SEC-TEST-008 | LOW | N/A | ni argent, ni santé, ni large public : service auto-hébergé pour quelques comptes invités ; `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |  |

## Not applicable
| ID | Why, with proof |
|---|---|
| REQ-CRYPT-003 | bcrypt absent : `grep -rniE "bcrypt" socle/src src` → 0 ; Argon2id seul |
| REQ-DATA-007 | aucun envoi de fichier ni import depuis une adresse fournie par un utilisateur : corps JSON seulement (`socle/src/http.js:122`), `grep -rniwE "multipart\|busboy\|formidable" src socle/src` → 0 ; les listes de menaces ajoutées sont lues comme du texte, bornées, jamais exécutées (voir SEC-CSRF-004) |
| SEC-AUTH-008 | aucune connexion par fournisseur externe : `grep -rniwE "oauth\|openid\|id_token\|redirect_uri" socle/src src` → 0 |
| SEC-SESS-005 | aucun JWT : `grep -rniwE "jwt\|jsonwebtoken\|jose" src web socle/src` → 0 |
| SEC-SESS-006 | aucun jeton de rafraîchissement : sessions serveur (voir SEC-SESS-005) |
| SEC-AUTHZ-005 | aucune notion de locataire : une instance surveille un réseau ; `grep -rniwE "tenants?\|organisations?\|workspaces?" src` → 0 |
| SEC-INJ-002 | aucun ORM : node:sqlite, requêtes préparées seulement |
| SEC-INJ-003 | aucune base documentaire : SQLite seulement ; JSON rangé en colonne texte |
| SEC-INJ-007 | aucun analyseur XML côté serveur : `grep -rniwE "xml2js\|sax\|libxml\|fast-xml\|DOMParser" src socle/src` → 0 (le navigateur ne lit en SVG que les pictogrammes et le QR code qu’il dessine lui-même) |
| SEC-XSS-002 | aucun texte riche ni Markdown rendu : synthèses de l’IA, constats et lignes de journaux affichés en texte brut (voir SEC-XSS-001) |
| SEC-XSS-007 | aucune redirection pilotée par paramètre ; `curl -sI "/login?next=https://evil.example"` → aucun Location (annexe B.4) |
| SEC-CSRF-006 | aucune redirection pilotée par paramètre : voir SEC-XSS-007 |
| SEC-API-006 | aucun GraphQL : `grep -rniwE "graphql\|apollo" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-API-008 | aucune opération monétaire ni crédit : `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; le plafond d’appels d’IA est un garde-fou de coût, compté localement (voir SEC-LLM-002) |
| SEC-DB-002 | SQLite embarqué sans rôle ni identifiant : `src/base.js:30` |
| SEC-DB-008 | le navigateur ne parle jamais à la base : SQLite côté serveur seulement |
| SEC-FILE-001 | aucun envoi de fichier : corps JSON seulement (`socle/src/http.js:122`) |
| SEC-FILE-002 | aucun envoi de fichier ; corps JSON bornés (voir SEC-API-010) |
| SEC-FILE-003 | aucun fichier d’utilisateur écrit ; seules écritures : la base et les listes de menaces, nommées par le serveur (`src/bouclier/menaces.js:75`) |
| SEC-FILE-004 | aucun fichier d’utilisateur servi ; le rapport PDF est produit par le serveur, en pièce jointe (`src/api.js:186`) |
| SEC-FILE-005 | aucun fichier d’utilisateur stocké |
| SEC-FILE-006 | aucun fichier partagé entre utilisateurs |
| SEC-FILE-007 | aucune image acceptée |
| SEC-FILE-008 | aucun import par adresse fournie par un utilisateur, hors des listes de menaces ajoutées par un administrateur sous renfort : voir SEC-CSRF-004 |
| SEC-PAY-001 | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement |
| SEC-PAY-002 | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement ; aucun webhook de paiement reçu |
| SEC-PAY-003 | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement ; aucun abonnement |
| SEC-PAY-004 | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement |
| SEC-PAY-005 | `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 : aucun paiement |
| SEC-NEXT-001 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-002 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-003 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-004 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-005 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-006 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-007 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-008 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-NEXT-009 | Node sans cadriciel, aucune dépendance (`package.json:5`) ; `grep -rniwE "next/\|nextjs\|use server\|vercel" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-BAAS-001 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-002 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-003 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-004 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-005 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-006 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-007 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-008 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-009 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-010 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BAAS-011 | `grep -rniwE "supabase\|firebase\|firestore\|postgrest" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 ; base SQLite embarquée côté serveur : `src/base.js:30` |
| SEC-BE-005 | aucun Django : serveur Node seul |
| SEC-BE-006 | aucun Flask ni FastAPI : serveur Node seul, aucun Python dans le dépôt (`git ls-files "*.py" \| wc -l` → 0) |
| SEC-BE-007 | aucun Python dans le dépôt : voir SEC-BE-006 |
| SEC-BE-008 | aucun PHP : `git ls-files "*.php" \| wc -l` → 0 |
| SEC-WP-001 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-WP-002 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-WP-003 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-WP-004 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-WP-005 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-WP-006 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-WP-007 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-WP-008 | application Node écrite ici : `grep -rniwE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |
| SEC-INFRA-005 | aucun stockage objet : `grep -rniwE "s3\.\|gcs\|azure\|bucket" src socle/src` → 0 (le seul « aws » du code est un motif de détection d’URL hostile de la sentinelle) |
| SEC-INFRA-006 | aucun nuage : service auto-hébergé, aucune clé IAM |
| SEC-INFRA-009 | aucune infrastructure décrite en code : `find . -name "*.tf" -o -name "Pulumi.yaml"` → 0 fichier |
| SEC-LLM-005 | aucun outil ni agent : le modèle reçoit des constats et rend du JSON relu champ par champ, sans appel de fonction (`grep -rniE "tool_choice\|function_call\|tool_use" src` → 0) ; aucune action ne dépend de sa réponse (voir SEC-LLM-003) |
| SEC-LLM-007 | aucune IA ouverte au public ni à la saisie libre : aucune route ne prend un texte pour le modèle ; seule la relecture d’un audit l’appelle, avec une consigne fixe (voir SEC-LLM-002, SEC-LLM-003) |
| SEC-TEST-008 | ni argent, ni santé, ni large public : service auto-hébergé pour quelques comptes invités ; `grep -rniwE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web socle/src socle/web/compte.js socle/web/graphes.js` → 0 |

## Anonymity (REQ-ANON-001 to -010)
Arbre de travail : 0 occurrence de la liste d’anonymat propre à ce dépôt (la liste commune moins le nom d’un hyperviseur dont la sentinelle sait lire les journaux) ; les motifs de l’annexe B.1 y relèvent les adresses fabriquées des essais et le nom `.env.local` du `.gitignore`. Historique local complet (93 commits, tous les arbres, tous les messages, auteurs et validateurs) : une seule identité, toutes les dates en UTC, aucune mention d’outil, aucun chemin de poste ; les messages et identités ne portent aucun terme de la liste ; les diffs de l’historique en portent 41 lignes, toutes des modèles d’équipement, retirés de l’arbre (cinq fichiers) par `f2ae7e0` : historique déjà publié → exposition résiduelle, action H12, détail dans le rapport hors dépôt. Aucun binaire image ni document dans tout l’historique. Le balayage est fait sur motifs et sur une liste finie : il ne prouve pas l’absence de ce que la liste ne nomme pas.

## Human actions required
Ce qu’aucun agent ne peut faire à la place de l’exploitant. Cette liste bloque la mise en production tant qu’elle n’est pas vide.

| # | Action | Contrôles | Étapes |
|---|---|---|---|
| H1 | Servir VIGIE en HTTPS | REQ-WEB-001, SEC-HDR-001, SEC-INFRA-001, SEC-TEST-005, REQ-DATA-002 | Dans le Hub : relais ou certificat de l’autorité locale pour VIGIE ; déclarer l’adresse du relais dans « Relais de confiance » (SOCLE_PROXYS) ; « Accès sans HTTPS » à Non ; vérifier `curl -sI https://<vigie>/ \| grep -i strict-transport-security` ; noter le résultat de testssl.sh. |
| H2 | Relais SMTP et adresses d’alerte | REQ-AUTH-014, SEC-PAY-007, SEC-LOG-004 | Réglages avancés de VIGIE dans le Hub : relais, port, chiffrement, identifiants, expéditeur, adresse publique ; SPF, DKIM et DMARC du domaine d’expédition ; chaque administrateur ajoute puis confirme son adresse dans Sécurité → Alertes par courriel. |
| H3 | GitHub | REQ-CI-001…005, GOV-003, GOV-005, SEC-INFRA-007/008, SEC-TEST-001…003, SEC-DEP-002/006/008 | Activer les Actions ; Settings → Branches : protéger `main` (pas de poussée forcée, contrôles requis : essais, secrets, identite, anonymat, analyse) ; Code security : Dependabot alerts, secret scanning et push protection, private vulnerability reporting ; 2FA sur le compte et sur chaque console de fournisseur. |
| H4 | Liste d’anonymat | REQ-ANON-003, REQ-CI-004, REQ-CI-001 | Sur le poste : gitleaks ; liste et crochet global `pre-commit` qui refuse un diff portant un terme ; sur GitHub : secret de dépôt `LISTE_ANONYMAT`, la liste commune SAUF le nom de l’hyperviseur que la sentinelle sait lire. Vérifier qu’un commit d’essai portant un terme est refusé par le crochet, puis par la vérification. |
| H5 | Brûler les secrets vus pendant le développement | SEC-SECRETS-006 | Régénérer chez leur fournisseur toute clé d’IA, jeton Telegram, clé UniFi ou jeton Cloudflare ayant servi aux essais ; dans le Hub, régénérer le jeton de service de VIGIE (HUB_TOKEN) et redéployer ; tourner SOCLE_CLE une fois (README, « Tourner la clé maîtresse »). |
| H6 | Clés restreintes, par environnement | REQ-CFG-003, SEC-SECRETS-005, GOV-004 | Clé UniFi d’intégration limitée aux groupes d’adresses et aux règles ; jeton Cloudflare limité au compte et aux zones (listes, règles WAF, réglage de sécurité) ; une clé d’IA dédiée à VIGIE ; un jeu pour la VM d’essai, un autre pour la production. |
| H7 | Chiffrement des disques | REQ-DATA-002, SEC-DB-003, SEC-PRIV-005 | LUKS (ou chiffrement du stockage de l’hyperviseur) sur l’hôte qui porte le volume de VIGIE. |
| H8 | Sauvegardes et exercices | REQ-DATA-003, SEC-DB-006 | Paire RSA 3072 bits créée hors de la machine de VIGIE (README, « Sauvegardes ») ; cron quotidien `docker exec -i <vigie> node src/cli.js sauvegarde < vigie-sauvegarde.pub > vigie-$(date -u +%F).sauv` ; copie hors hôte, trente jours ; restauration réelle sur la VM, datée ici. |
| H9 | Hôtes | SEC-INFRA-003 | Pare-feu (seuls les ports publiés ; le port syslog ouvert au seul réseau de la passerelle), SSH par clé sans root, mises à jour de sécurité automatiques. |
| H10 | Disponibilité vue de l’extérieur | SEC-LOG-005 | Une sonde externe sur `/api/health`, ou décision écrite : service de réseau local seulement, sondes du Hub suffisantes. |
| H11 | Journaux centralisés | SEC-LOG-003 | Transférer les journaux du conteneur (dont le journal de sécurité) vers un collecteur hors de l’hôte. |
| H12 | Historique publié | REQ-ANON-002 | L’historique publié de `vigie` garde des modèles d’équipement (rapport hors dépôt). Choisir : le laisser (exposition faible, déjà publique) ; ou recréer le dépôt depuis l’arbre propre (supprimer l’ancien, vérifier les bifurcations, pousser l’historique réécrit) ; jamais de réécriture silencieuse d’un historique partagé. |
| H13 | Domaine | REQ-ANON-009, SEC-INFRA-002 | Si VIGIE reçoit un nom public : protection WHOIS, verrou du registraire, 2FA, enregistrement CAA. |
| H14 | Crible au déploiement | SEC-INFRA-004, SEC-TEST-003, SEC-TEST-004 | Sur la VM : `trivy image ghcr.io/codexx64/vigie:1.2.7` sans CRITICAL ni HIGH corrigeable ; `zap-baseline.py -t http://<vm>:<port>` ; résultats notés ici. |
| H15 | Sous-traitants hors UE | SEC-PRIV-006 | Si le relais SMTP, Telegram ou Cloudflare sont retenus : accord de traitement accepté, ou choix d’un service européen ou auto-hébergé. |
| H16 | Clé maîtresse hors ligne | REQ-DATA-003, SEC-DB-006 | Garder une copie hors ligne de SOCLE_CLE, à part des sauvegardes de la base. |
| H18 | Fournisseur d’IA en nuage | SEC-LLM-002, SEC-LLM-006, SEC-PRIV-006 | Si un mode nuage est choisi : plafond de dépense mensuel chez le fournisseur, réglage « pas d’entraînement sur les données », accord de traitement. |
| H19 | Déclarer la passerelle comme émetteur | — (fonctionnement) | Bouclier → Réglages → « Liste blanche et émetteurs » : l’adresse de la passerelle UniFi (et des hôtes qui envoient leurs journaux). Sans elle, VIGIE signale mais ne bloque plus rien seule (C1). |

## Secrets inventory
| Secret | Where it lives | Scope | Rotation procedure | Last rotated |
|---|---|---|---|---|
| SOCLE_CLE (clé maîtresse) | coffre du Hub, ou `secrets/socle_cle` (installation seule), jamais dans le volume | scelle TOTP et secrets des réglages | README, « Tourner la clé maîtresse » ; rescellage vérifié par essai | à la création |
| VIGIE_HUB_TOKEN | coffre du Hub, environnement du conteneur | lecture, audits et actions du Hub ; clé des jetons dérivés | régénérer dans le Hub, redéployer (runbook, étape 3) | à la création |
| Jetons dérivés MapMyLAN, NEXARC, SYNAPSE | calculés par le Hub, environnement | une source chacun | régénérer le jeton de la source dans le Hub | à la création |
| Clé d’IA en nuage | base, scellée | relecture des audits | Réglages → IA (renfort) ; `node src/cli.js secrets retirer ia` | — |
| Jeton du bot Telegram | base, scellé | envoi des alertes | BotFather → revoke ; Réglages → Telegram (renfort) | — |
| Clé de la billetterie | base, scellée | création de tickets | chez la billetterie ; Réglages → Billetterie (renfort) | — |
| Jeton docker-control | base, scellé | lecture des conteneurs | docker-control ; Réglages → docker-control (renfort) | — |
| Clé UniFi d’intégration | base, scellée | groupes d’adresses et règles de la passerelle | console UniFi ; Bouclier → Passerelle (renfort) | — |
| Jeton Cloudflare | base, scellé | listes, règles, mode Under Attack | tableau de bord Cloudflare ; Bouclier → Cloudflare (renfort) | — |
| Jeton de la liste des pare-feu | base, scellé | lecture de la liste des adresses bloquées | Bouclier → nouveau jeton (renfort) : l’ancien cesse de valoir | — |
| Jetons des sondes Suricata | base, par empreinte | envoi d’événements EVE | Bouclier → sonde → retirer puis recréer (renfort) | — |
| SOCLE_JETON_INSTALLATION | coffre du Hub | premier compte seulement | sans effet une fois l’installation faite | à la création |

## Incident runbook
```bash
# 1. Détecter : Sécurité → Journal (refus, verrous, jetons refusés) ; Hub → VIGIE → Journaux
# 2. Fermer toutes les sessions sauf la sienne (administrateur, renfort)
curl -X POST https://<vigie>/api/compte/admin/sessions/fermer-tout -b <cookie> -H 'X-CSRF: <jeton>' -H 'Origin: https://<vigie>'
# 3. Couper le Hub : régénérer HUB_TOKEN dans le Hub, puis Redéployer VIGIE
# 4. Retirer les secrets des réglages, service en marche, puis les révoquer chez leurs fournisseurs
docker exec <vigie> node src/cli.js secrets retirer
# 5. Forcer un nouveau mot de passe : Comptes → compte → Réinitialiser (lien à usage unique, 20 minutes)
# 6. Restaurer, depuis le poste qui garde la clé privée, puis remettre la base dans le volume
node src/cli.js restaurer vigie-sauvegarde.pem vigie.db < vigie-AAAA-MM-JJ.sauv
docker stop <vigie> && docker run --rm -v <volume>:/data -v "$PWD":/b busybox sh -c 'cp /b/vigie.db /data/vigie.db && rm -f /data/vigie.db-wal /data/vigie.db-shm && chown 10004:10004 /data/vigie.db && chmod 600 /data/vigie.db' && docker start <vigie>
#    Base sauvegardée avant une rotation : poser la clé d'alors dans SOCLE_CLE_ANCIENNE avant de démarrer
# 7. Vérifier la chaîne du journal : Comptes → Journal de sécurité (« chaîne intacte »)
```
Qui : l’exploitant de l’instance tient chaque étape ; révoquer chez UniFi, Cloudflare, Telegram et le fournisseur d’IA ; support.github.com pour le dépôt. Communiquer : prévenir les comptes concernés ; si des données personnelles ont pu être lues (comptes, noms d’appareils, journaux d’hôtes), notifier l’autorité de contrôle sous 72 heures à compter de la découverte. Joué de bout en bout le 2026-10-19 : `outils/exercice-incident.mjs`, 22 vérifications.

## Inventory
Routes publiques : `GET /api/health` (`{ok:true}` seulement), `GET /.well-known/security.txt`, `GET /api/compte/etat`, cérémonies de connexion et d’installation du socle, `POST /api/sonde/eve` (jeton de sonde), `GET /api/bouclier/liste.txt` (jeton de liste, ou lecture), fichiers de `web/` et `socle/web/` (tout segment commençant par un point → 404). Session, Hub et jetons dérivés : 44 routes sous `/api/`, chacune balayée contre la table des droits (`test/vigie.test.js`) ; flux en direct `GET /api/sentinelle/flux` (session seule). Récepteur syslog UDP et TCP (5514), émetteurs déclarés ou, à défaut, adresses privées dont les lignes ne déclenchent rien seules.

Données : `vigie.db` (comptes, sessions, jetons hachés, journal chaîné, audits, constats, événements, actions, blocages, alertes de la sentinelle, réglages aux secrets scellés — sensibilité : personnelle et opérationnelle), listes de menaces sur le volume, volume `/data` en 0700, base en 0600 ; adresses observées par le bouclier en mémoire seulement.

Tiers (chez l’exploitant sauf mention) : MapMyLAN, NEXARC, docker-control, SYNAPSE, Ollama et le Hub ; la passerelle UniFi ; les éditeurs des listes de menaces (téléchargement seul) ; en option, chez des fournisseurs : IA en nuage (Anthropic, OpenAI, Moonshot), Telegram, Cloudflare, relais SMTP.

## Appendix B sweep
Relancé à chaque génération de ce fichier (bash, LC_ALL=C.UTF-8), deux fois de suite, sorties identiques ; B.5 est dans NO-VIBE.md.

| # | Commande | Résultat | Justification |
|---|---|---|---|
| B.1.1 | `git log --all --format='%an <%ae>' \| sort -u` | `CodexX64 <CodexX64@users.noreply.github.com>` | le pseudonyme seul |
| B.1.2 | `git log --all --format='%cn <%ce>' \| sort -u` | `CodexX64 <CodexX64@users.noreply.github.com>` | le pseudonyme seul |
| B.1.3 | `git log --all --format='%B' \| rg -in 'co-authored-by\|generated (by\|with)\|assistant\|as an ai' \| wc -l` | `0` |  |
| B.1.4 | `find . -path ./node_modules -prune -o \( -name .ai -o -name .cursor -o -name .aider -o -name .continue -o -name .windsurfrules \) -print \| wc -l` | `0` |  |
| B.1.5 | `find . -path ./node_modules -prune -o -regextype posix-extended -regex '.*/(CLAUDE\|AGENTS?\|PROMPTS?\|GEMINI)\.md' -print \| wc -l` | `0` |  |
| B.1.6 | `git log --all --name-only --format= \| sort -u \| rg -i '(^\|/)(CLAUDE\|AGENTS?\|PROMPTS?\|GEMINI)\.md$\|copilot-instructions\|\.cursor\|\.aider' \| wc -l` | `0` | aucun fichier de consignes d’outil dans tout l’historique |
| B.1.7 | `rg -n 'copilot-instructions' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `0` |  |
| B.1.8 | `git grep -nIiE` avec le motif « personal infrastructure, paths and networks » de l’annexe B.1, hors des deux fichiers de conformité | 40 lignes | le nom `.env.local` du `.gitignore` ; des adresses fabriquées dans les essais et la vitrine (10.9.x, et le classement des plages privées que le bouclier doit savoir reconnaître) ; aucune adresse d’un réseau réel |
| B.1.9 | `git log --all -p -- . ':!SECURITY.md' ':!NO-VIBE.md'` filtré par le motif « infrastructure personnelle » de l’annexe B.1, compté | `82` | les noms des produits dont la sentinelle sait lire les journaux (NAS, Synology, WireGuard, Tailscale, l’hyperviseur) : objet du logiciel ; aucun terme d’infrastructure personnelle |
| B.1.10 | `git log --all --format='%aI' \| rg -v '\+00:00' \| wc -l` | `0` | tout l’historique en UTC |
| B.1.11 | `git log --all --format='%cI' \| rg -v '\+00:00' \| wc -l` | `0` | idem pour le validateur |
| B.1.12 | `git grep` de tout l’historique (`$(git rev-list --all)`) avec le motif des chemins de poste et d’espaces de travail d’outils (gardé hors dépôt), lignes distinctes comptées | `11` | toutes dans `test/sentinelle.test.js` : des lignes de journaux fabriquées (« home=/home/svc », « PWD=/home/alice ») que les décodeurs doivent lire ; aucun chemin d’un poste ni d’un espace de travail d’outil |
| B.1.13 | `git log --all --name-only --format= \| sort -u \| rg -i '\.(png\|jpe?g\|pdf\|mp4\|gif\|webp\|ico)$' \| wc -l` | `0` | aucun binaire image ou document dans tout l’historique : exiftool n’a rien à lire |
| B.1.14 | `git log --all -p -- . ':!SECURITY.md' ':!NO-VIBE.md'` filtré par la liste d’anonymat propre à ce dépôt (hors dépôt), compté | `41` | des modèles d’équipement, dans des diffs déjà publiés ; retirés de l’arbre par `f2ae7e0` ; exposition résiduelle → H12 et rapport hors dépôt |
| B.1.15 | messages, auteurs et validateurs de tout l’historique filtrés par la même liste, comptés | `0` |  |
| B.1.16 | arbre de travail filtré par la même liste, hors des deux fichiers de conformité, compté | `0` |  |
| B.2.1 | `gitleaks git --no-banner --redact . 2>&1 \| tail -1` | `no leaks found` | tout l’historique |
| B.2.2 | `gitleaks dir --no-banner --redact . 2>&1 \| tail -1` | `no leaks found` | arbre de travail |
| B.2.3 | `git grep -nIiE '(api[_-]?key\|secret\|token\|password\|bearer)\s*[=:]\s*["'"'"'][^"'"'"']{8,}' -- . ':!SECURITY.md' ':!NO-VIBE.md'` | 3 lignes | le gabarit `{{config.HUB_TOKEN}}` du manifeste du Hub, le jeton fabriqué de la vitrine, le vecteur publié de la RFC 6238 dans un essai du socle |
| B.2.4 | `git grep -nI -e '-----BEGIN (RSA\|EC\|OPENSSH\|PGP) PRIVATE' -- . ':!SECURITY.md' ':!NO-VIBE.md' \| wc -l` | `0` |  |
| B.2.5 | `rg -ni 'sk_live\|service_role\|xox[baprs]-\|-----BEGIN' web socle/web \| wc -l` | `0` | aucune étape de construction : le navigateur reçoit web/ et socle/web tels quels |
| B.2.6 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18150/.env` | `404` | instance locale ; tout segment caché répond 404 |
| B.2.7 | `git log --all -p -- . ':!SECURITY.md' ':!NO-VIBE.md' \| rg -n 'sk-ant-\|sk_live_\|AKIA[0-9A-Z]{16}\|ghp_[A-Za-z0-9]{30}\|xox[bp]-\|-----BEGIN [A-Z]* ?PRIVATE' \| wc -l` | `1` | la clé d’IA fabriquée des faux voisins (`test/faux.js`, « sk-ant-essai-… ») ; aucune vraie clé |
| B.3.1 | `rg -n 'dangerouslySetInnerHTML\|innerHTML *=\|outerHTML *=\|document\.write' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 2 lignes | le gabarit du socle : balisage écrit dans le code, valeurs posées en nœuds texte ou attributs (SEC-XSS-001) |
| B.3.2 | `rg -n 'eval\(\|new Function\(\|execSync\|child_process\|os\.system\|subprocess.*shell=True' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 5 lignes | outils et essais seulement, sans shell, binaire fixe et arguments en tableau : l’exercice d’incident lance VIGIE et sa ligne de commande (`process.execPath`), les essais la ligne de commande et openssl ; aucune dans `src/` |
| B.3.3 | `rg -n '[^.]\bexec\(' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `0` |  |
| B.3.4 | `rg -n 'f"SELECT\|"SELECT .*" *\+\|\$\{.*\} *FROM\|\.raw\(\|query\(.*\+ *req\.' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `0` |  |
| B.3.5 | `rg -n 'Math\.random\|uuidv1\|new Random\(\)' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `0` |  |
| B.3.6 | `rg -n 'verify *= *False\|rejectUnauthorized: *false\|InsecureSkipVerify' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 2 lignes | justifiées ligne à ligne dans le tableau « B.3 — TLS sans vérification par autorité » ci-dessous |
| B.3.7 | `rg -n 'jwt\.decode\(\|algorithms: *\[.*none\|verify: *false' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `0` |  |
| B.4.1 | `curl -sI http://localhost:18150/ \| rg -i 'content-security\|x-content-type\|referrer-policy\|permissions-policy\|x-frame\|cross-origin' \| wc -l` | `7` | CSP à nonce sans joker, nosniff, no-referrer, DENY, COOP et CORP same-origin, Permissions-Policy ; HSTS dès que la requête est chiffrée (H1) |
| B.4.2 | `curl -sI http://localhost:18150/ \| rg -i '^(server\|x-powered-by\|x-aspnet\|x-generator)' \| wc -l` | `0` |  |
| B.4.3 | `curl -sI -H 'Origin: https://evil.example' http://localhost:18150/api/etat \| rg -i access-control \| wc -l` | `0` | aucun CORS : même origine seulement |
| B.4.4 | `curl -sI 'http://localhost:18150/login?next=https://evil.example' \| rg -i '^location' \| wc -l` | `0` | aucune redirection : 404 |
| B.4.5 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18150/.git/config` | `404` |  |
| B.4.5b | `…/v/x/../.git/config` puis `…/v/1.2.7/%2e%2e/src/config.js` | `404` ; `404` | l’adresse versionnée ne sort pas de `web/` |
| B.4.6 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18150/api/reglages` | `401` | les réglages demandent une session d’administrateur |
| B.4.7 | trente `POST /api/compte/connexion` d’un mot de passe faux, codes comptés | `3 401, 27 428` | trois échecs, puis preuve de travail exigée (428) ; 429 et verrouillage au-delà |
| B.4.8 | quatorze `GET /api/etat` avec un jeton inventé, codes comptés | `10 401, 4 429` | un jeton inventé : 401, puis 429 une fois le plafond d’échecs de l’adresse atteint |

### B.3 — TLS sans vérification par autorité, ligne à ligne
| Ligne | Ce qu’elle est | Pourquoi elle est admise |
|---|---|---|
| `src/bouclier/tls.js:22` | la sonde `observer()` du certificat de la passerelle, avant épinglage | atteinte seulement par `POST /api/bouclier/unifi/sonde`, administrateur sous renfort ; aucune donnée applicative envoyée ; ne rend que l’empreinte SHA-256, que l’administrateur confirme ; toute connexion suivante est épinglée sur elle |
| `src/sources.js:231` | la sonde TLS de l’audit, sur les appareils du périmètre | l’objet même de la règle : relever le certificat et les protocoles qu’un appareil accepte, y compris un certificat invalide ; poignée de main seule, aucune donnée applicative, périmètre de MapMyLAN seulement |

## Exploratory probing (SEC-TEST-007)
Sondage exploratoire du 2026-10-19, rejoué à chaque génération de ce fichier sur une instance neuve reliée à ses faux voisins (vrais comptes, vrai jeton du Hub, vrai récepteur syslog) : 32 cas d’abus tentés, chacun avec la réponse obtenue et celle qu’exige la règle ; un seul écart arrête la génération.

| # | Cas d’abus | Tenté | Obtenu | Attendu |
|---|---|---|---|---|
| P1 | anonyme sur l’état | `GET /api/etat` | 401 | 401 |
| P2 | lecture seule qui lance un audit | `POST /api/audits (lecture)` | 403 | 403 |
| P3 | membre qui isole un appareil | `POST /api/actions {quarantine} (membre)` | 403 | 403 |
| P4 | jeton dérivé qui isole un appareil | `POST /api/actions {quarantine} (jeton dérivé)` | 403 | 403 |
| P5 | jeton du Hub qui force une isolation | `POST /api/actions {quarantine, forcer} (Hub)` | 403 | 403 |
| P6 | jeton du Hub sur les réglages | `GET /api/reglages (Hub)` | 403 | 403 |
| P7 | jeton du Hub qui change la clé d’IA | `PUT /api/reglages/ia (Hub)` | 403 | 403 |
| P8 | jeton dérivé falsifié | `GET /api/etat, cer_mapmylan_<64 zéros>` | 401 | 401 |
| P9 | jeton du Hub qui retombe sur la session | `GET /api/reglages, jeton faux + cookie admin` | 401 | 401 |
| P10 | sonde sans jeton de sonde | `POST /api/sonde/eve (session admin)` | 401 | 401 |
| P11 | jeton de sonde inventé | `POST /api/sonde/eve, vgs_ au hasard` | 401 | 401 |
| P12 | liste des pare-feu, jeton faux | `GET /api/bouclier/liste.txt?jeton=faux` | 401 | 401 |
| P13 | blocage d’une adresse privée | `POST /api/bouclier/bloquer {10.0.0.1} (Hub)` | 400 | 400 |
| P14 | blocage d’un résolveur de la liste blanche | `POST /api/bouclier/bloquer {1.1.1.1} (Hub)` | 400 | 400 |
| P15 | billetterie vers les métadonnées | `PUT /api/reglages/billetterie {url:https://169.254.169.254/} (admin)` | 400 | 400 |
| P16 | liste de menaces vers les métadonnées | `PUT /api/reglages/bouclier {listesPropres:[https://[::ffff:169.254.169.254]/]} (admin)` | 400 | 400 |
| P17 | billetterie avec identifiants dans l’adresse | `PUT /api/reglages/billetterie {url:https://u:p@x.exemple/} (admin)` | 400 | 400 |
| P18 | champ inconnu | `PUT /api/reglages/veille {debug:true} (admin)` | 400 | 400 |
| P19 | prototype pollué | `PUT /api/reglages/bouclier {"__proto__":{…}} (admin)` | 400 | 400 |
| P20 | paramètre non déclaré | `GET /api/etat?debug=1` | 400 | 400 |
| P21 | paramètre inconnu sur une route qui rend tôt | `GET /api/constats?appareil=a&script=id` | 400 | 400 |
| P22 | corps géant | `POST /api/sentinelle/essai, 200 Kio (admin)` | 413 | 413 |
| P23 | écriture sans jeton anti-CSRF | `POST /api/audits sans X-CSRF (membre)` | 403 | 403 |
| P24 | écriture depuis une autre origine | `POST /api/audits, Origin: https://evil.example (membre)` | 403 | 403 |
| P25 | identifiant d’audit piégé | `GET /api/audits/..%2F..%2Fetc` | 404 | 404 |
| P26 | secrets dans les réglages | `GET /api/reglages (admin) : clé d’IA ou jeton Telegram en clair ?` | false | false |
| P27 | flux en direct sans session | `GET /api/sentinelle/flux` | 401 | 401 |
| P28 | banc d’essai des règles par un membre | `POST /api/sentinelle/essai (membre)` | 403 | 403 |
| P29 | journaux forgés par une machine du réseau | `force brute SSH puis succès en syslog, aucun émetteur déclaré : 45.155.205.99 bloquée ?` | false | false |
| P30 | ligne hostile de 16 Kio | `hostapd: wlan0` suivi de 16 Kio de « : » en syslog : VIGIE répond en moins de 100 ms ? | true | true |
| P31 | couper la sentinelle sans renfort | `PUT /api/reglages/sentinelle {actif:false}, renfort retiré` | 403 | 403 |
| P32 | jetons du Hub inventés en rafale | `douze GET /api/etat, jetons faux` | bloqué (429) | bloqué (429) |

Suivi du 2026-10-25 (1.2.8) : mise en page, flux de la sentinelle et relais de confiance. Socle 6f2c864 embarqué : un seul écart entre cartes (`--ecart`, 16 px, 12 px en Console et sur petit écran), deux colonnes finissant à la même ligne, en-têtes de carte de même hauteur, cartes des pages Sécurité et Comptes l'une sous l'autre, et un contrôle de mise en page qui relève tout écart différent et toute colonne inégale, sans comparer une carte qui finit sa transition de survol. VIGIE prend cet écart partout (`web/vigie.css:10`) : la notice des événements critiques du tableau de bord (18 px jusqu'ici), les avis du Bouclier et de la Sentinelle, la carte « En direct », les filtres des constats et la référence des règles ; une carte étirée par sa colonne ou sa rangée (Relecture de l'IA, Sources, cartes de réglages) centre son contenu au lieu de laisser un vide en bas (`web/vigie.css:13`, `web/vigie.css:16`) ; le nom d'un hôte n'est plus rogné dans les constats par hôte, la règle parente s'écrit d'une pièce, le niveau retenu par l'essai d'une ligne se pose à côté de sa description. La page Sentinelle ne fermait pas son flux en direct : chaque visite gardait sa connexion jusqu'au prochain événement, et au-delà de six le navigateur ne chargeait plus rien ; il se ferme dès que la page est quittée (`web/sentinelle.js:74`). Le parcours du navigateur passe désormais par la Sentinelle et ses vues (direct, alertes, hôtes, sources et règles, réglages avec l'essai d'une ligne) et par les pages de détail du Bouclier. Relais de confiance : ouvert en HTTPS par Relay (tunnel Cloudflare), VIGIE se croyait en HTTP et refusait les clés d'accès, le relais de confiance du manifeste étant vide (`X-Forwarded-Proto` n'est lu que d'un relais déclaré, `socle/src/http.js:43`) ; défaut désormais : le réseau Docker du Hub (`hub.json`, « Relais de confiance »), une adresse du réseau local n'est jamais de confiance. Essai : `test/vigie.test.js:590` (manifeste). Les références de ligne du tableau sont recalées sur l'arbre, socle compris. Aucune route ne change, aucun contrôle ne change de statut. Essais : 57 du service, 77 du socle ; parcours du navigateur dans les quatre gammes (SOMA, Console, Exploitation, Lavande) : 168 écrans × largeurs chacune, 0 défaut, 0 erreur de console ; Lavande repassée cinq fois, cinq fois sans défaut.

Suivi du 2026-10-30 (1.2.9) : nouveau logo. L'icône de l'onglet (`web/icone.svg`) et la marque de la barre et de l'écran de connexion (`web/app.js:17`, tracé posé par createElementNS, aucun balisage injecté) prennent le nouveau logo. Fichier SVG nettoyé : ni métadonnées, ni commentaire. Aucun contrôle ne change de statut. Essais : 57 du service. Parcours du navigateur : 168 écrans × largeurs, 0 défaut, 0 erreur de console.

Suivi du 2026-10-30 (1.2.10) : logos. Le logo complet (marque et nom) et la marque seule sont tracés dans la page par createElementNS, en couleur du texte (`web/app.js:18`) ; aucun balisage injecté, aucune donnée. L'icône de l'onglet reprend le fichier favicon du dossier Logo, nettoyé (ni métadonnées, ni commentaire). Aucun contrôle ne change de statut. Essais et parcours du navigateur repassés.

Suivi du 2026-10-30 (1.3.0) : assistant de configuration et nouveautés (socle 1661aef). La première installation passe par l'assistant, obligatoire : VIGIE répond 428 à toute route du service tant qu'un administrateur ne l'a pas terminé ; après une mise à jour, seuls les réglages nouveaux sont demandés. Réglages de l'assistant : sources MapMyLAN et NEXARC (jetons scellés), port syslog publié, IA des audits (mode, Ollama, fournisseur, modèle, clé scellée, plafond), plus ceux communs du socle. Chaque valeur est validée par la configuration même du service (lireConfig, contrôles croisés) ; un secret est scellé dans reglages.json (0600) sous la clé maîtresse, jamais rendu ; l'environnement l'emporte toujours. Routes /api/compte/reglages : administrateur, origine et anti-CSRF, renfort hors première configuration, journal reglages.poses sans valeur. Processus superviseur : relance du service quand un réglage change, signal d'arrêt transmis. Fenêtre « Quoi de neuf » (nouveautes.json, une fois par compte et par version). README : logo, affiche, captures, première configuration ; médias sans métadonnées. Aucun contrôle ne change de statut. Essais et parcours du navigateur repassés.

## Suivi du 2026-11-01 (1.3.1) : image et vérification sous l'organisation Nesaris

Aucun contrôle ne change de statut ; aucun changement de comportement du service.

- image de base Node 24.22.1, épinglée par empreinte : la 24.21.0 portait une faille critique exploitée (CVE-2026-111497) et plusieurs failles hautes ; paquets du système mis à jour à la construction ; npm, npx, corepack et yarn retirés des étapes d'exécution (aucune dépendance npm à l'exécution) ;
- vérification continue : gitleaks 8.30.1 en ligne de commande, archive contrôlée par son empreinte SHA-256, sur tout l'historique (l'action exigeait une licence sur un dépôt d'organisation) ; heure UTC acceptée sous ses deux écritures par git (« +00:00 » et « Z ») ; termes d'anonymat possibles en mot entier (« ~ ») ; liste d'anonymat posée au niveau de l'organisation Nesaris ; essais sous Node 24.22.1 ;
- images publiées sous ghcr.io/nesaris.

Contrôles rejoués avant livraison : gitleaks sur tout l'historique (aucune fuite), identité et fuseau des nouveaux commits (CodexX64, UTC, aucune mention d'outil), liste d'anonymat sur l'arbre et les nouveaux commits (aucune correspondance).

## Suivi du 2026-11-12 (1.4.0) : accueil, carnet et carte des attaques

Aucun contrôle ne change de statut. Ce que la version ajoute, au regard du référentiel :

- route `GET /api/accueil` : lecture (session), jeton du Hub et jeton dérivé, comme `/api/etat` ; paramètre `heures` validé (entier de 1 à 720), tout autre paramètre refusé ; entrée ajoutée à la table des droits des essais (chaque route y est vérifiée) ;
- table `attaques` : une ligne par heure, adresse publique, cible, port et nature ; compteurs tenus en mémoire (au plus 50 000 clés, versées dès ce plafond) puis écrits en une transaction toutes les dix secondes ; gardée 30 jours (`carnetJours`, entier de 1 à 365, validé) ; seules des adresses publiques y entrent ; aucune donnée personnelle de compte ;
- nouvelles destinations sortantes, fixes et en HTTPS : les fichiers « delegated » des cinq registres régionaux (ftp.arin.net, ftp.ripe.net, ftp.apnic.net, ftp.lacnic.net, ftp.afrinic.net), une fois par semaine ; réponse lue par morceaux et bornée à 80 Mio, écrite à côté puis renommée (0600), gardée si le nouveau fichier n'a pas de blocs ; aucune adresse réglable, donc aucune requête vers une destination choisie par un utilisateur ;
- déclarer un émetteur depuis l'accueil ou le bouclier passe par la route existante `PUT /api/reglages/bouclier` : administrateur et renfort, adresse validée, journal `reglages.bouclier` ;
- interface : tout est construit nœud par nœud (h(), createElementNS, nœuds texte), aucun balisage injecté ; les contours de la carte sont des données publiques (Natural Earth, domaine public), fabriquées hors ligne par `outils/carte-monde.mjs` et servies par VIGIE, aucun appel à un tiers depuis le navigateur.

Contrôles rejoués avant livraison : 63 essais ; parcours du navigateur dans les quatre gammes et en SOMA sombre, 231 écrans × largeurs chacun, aucun défaut de mise en page, aucune erreur ; gitleaks sur tout l'historique ; identité et fuseau des nouveaux commits (CodexX64, UTC, aucune mention d'outil) ; liste d'anonymat sur l'arbre et les nouveaux commits.

## Suivi du 2026-11-12 (1.5.0) : position du menu

Aucun contrôle ne change de statut. Socle 12fc8cc embarqué (de 1661aef) : le menu se place à gauche, en haut, en bas ou à droite. La valeur du service vient de `SOCLE_DISPOSITION` (posée par le Hub par `{{hub.disposition}}`, d'où `minHubVersion` relevé à 0.17.0) ; liste fermée, toute autre valeur arrête le démarrage. Chaque personne peut en choisir une autre : elle reste dans son navigateur (localStorage, clé `socle.disposition`) et n'est jamais envoyée au serveur. Pour l'appliquer avant le premier rendu, la page reçoit un court script en ligne porteur du nonce de la requête (rien n'est ajouté à la politique de contenu, ni `unsafe-inline`) ; il ne lit que cette clé et n'accepte que les quatre valeurs. Le geste (appui long, puis glisser vers un bord) et la petite fenêtre de choix sont construits nœud par nœud, sans balisage. Aucune route, aucune sortie réseau, aucune donnée nouvelle côté serveur. Le socle apporte aussi ses reprises intermédiaires (mise en page mesurée sous la ligne de flottaison, assistant : relais et adresse publique détectés proposés préremplis). Contrôles rejoués : 63 essais (deux essais réseau de la veille sensibles à la charge passent seuls, comme avant) ; captures dans les quatre positions à 1280 et 390 px, sans débordement ni erreur de page ; gitleaks ; identité et fuseau des nouveaux commits (CodexX64, UTC, aucune mention d'outil) ; liste d'anonymat sur l'arbre et les nouveaux commits.
