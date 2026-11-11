"""Catalogue français : message anglais (tel qu'écrit dans le code) -> traduction.

Les {paramètres} doivent être identiques des deux côtés. `tests/test_i18n.py` vérifie que
chaque message du code a sa traduction, sans entrée orpheline ni paramètre divergent.
"""

FR: dict[str, str] = {
    # ------------------------------------------------------------------ lanceur
    "[Y/n]": "[O/n]",
    "[y/N]": "[o/N]",
    "Creating the local environment (.venv)…": "Création de l'environnement local (.venv)…",
    "Cannot create .venv (is python3 -m venv available?)": (
        "Impossible de créer .venv (python3 -m venv indisponible ?)"
    ),
    "Installation failed. Check your connection and try again.": (
        "Installation échouée. Vérifiez votre connexion puis relancez."
    ),
    "Modules installed.": "Modules installés.",
    "Checking the installation…": "Vérification de l'installation…",
    "Python {need}+ required (found {found}).": "Python {need}+ requis (trouvé {found}).",
    "Native Windows is not supported: use WSL2 (see README).": (
        "Windows natif non pris en charge : utilisez WSL2 (voir README)."
    ),
    "Untested system: {platform}.": "Système non testé : {platform}.",
    "Missing modules: {modules}": "Modules manquants : {modules}",
    "Create a local environment (.venv) and install them?": (
        "Créer un environnement local (.venv) et les installer ?"
    ),
    "Install them with: pip install --require-hashes -r requirements.lock": (
        "Installez-les avec : pip install --require-hashes -r requirements.lock"
    ),
    "weasyprint missing (PDF export unavailable, HTML/JSON OK)": (
        "weasyprint absent (export PDF indisponible, HTML/JSON OK)"
    ),
    "All set.": "Tout est en place.",
    "Nothing to remove: the local environment does not exist.": (
        "Rien à supprimer : l'environnement local n'existe pas."
    ),
    "Will be removed:": "Seront supprimés :",
    "(scan history is kept; add --purge-data to erase it)": (
        "(l'historique des scans est conservé ; ajoutez --purge-data pour l'effacer)"
    ),
    "Confirm?": "Confirmer ?",
    "Cancelled.": "Annulé.",
    "Removed. The program folder itself remains: delete it by hand.": (
        "Supprimé. Le dossier du programme lui-même reste : supprimez-le à la main."
    ),
    "Type a domain (e.g. example.com) or a command: scan, history, diff, report.": (
        "Tapez un domaine (ex. exemple.fr) ou une commande : scan, history, diff, report."
    ),
    "`help` for help, `uninstall` to remove the local environment, `exit` to quit.": (
        "`help` pour l'aide, `uninstall` pour supprimer l'environnement local, `exit` pour quitter."
    ),
    # ------------------------------------------------------------------ CLI
    "Sonde (passive) — web + email security audit, public information only.": (
        "Sonde (passif) — audit de sécurité web + email, informations publiques uniquement."
    ),
    "Show the version.": "Affiche la version.",
    "Language of messages and reports (en, fr). Default: SONDE_LANG, else en.": (
        "Langue des messages et des rapports (en, fr). Défaut : SONDE_LANG, sinon en."
    ),
    "Overall grade: ": "Note globale : ",
    "{n} check(s) not completed ({ids}): the grade is indicative.": (
        "{n} contrôle(s) non réalisé(s) ({ids}) : la note est indicative."
    ),
    "Scan saved as #{id}.": "Scan enregistré sous le n° {id}.",
    "PASSIVE audit: headers, TLS, DNS, email. No intrusion, no authorization needed.": (
        "Audit PASSIF : en-têtes, TLS, DNS, messagerie. Aucune intrusion, aucune autorisation "
        "requise."
    ),
    "Domain or URL to audit.": "Domaine ou URL à auditer.",
    "Limit to web or email.": "Limiter à web ou email.",
    "Additional DKIM selector.": "Sélecteur DKIM supplémentaire.",
    "JSON output on stdout (no live display).": "Sortie JSON sur stdout (sans affichage live).",
    "Do not save the scan in the history.": "Ne pas enregistrer le scan dans l'historique.",
    "Option: public subdomains (crt.sh), without contacting the target.": (
        "Option : sous-domaines publics (crt.sh), sans contacter la cible."
    ),
    "Invalid target:": "Cible invalide :",
    "Invalid option:": "Option invalide :",
    "Scan not saved:": "Scan non enregistré :",
    "History unavailable:": "Historique indisponible :",
    "Generate the report of a saved scan (HTML, PDF or JSON).": (
        "Génère le rapport d'un scan enregistré (HTML, PDF ou JSON)."
    ),
    "Scan number (see `history`).": "N° du scan (voir `history`).",
    "Report format.": "Format du rapport.",
    "Output file (JSON: stdout if omitted).": "Fichier de sortie (JSON : stdout si omis).",
    "Light background, saves ink (printing).": "Fond clair, économe en encre (impression).",
    "Scan #{id} not found.": "Scan n°{id} introuvable.",
    "(see `history <domain>`)": "(voir `history <domaine>`)",
    "Report failed:": "Rapport impossible :",
    "{path} is a directory:": "{path} est un dossier :",
    "give a file name.": "indiquez un nom de fichier.",
    "Cannot write file:": "Écriture impossible :",
    "{fmt} report written:": "Rapport {fmt} écrit :",
    "Scan history of a domain.": "Historique des scans d'un domaine.",
    "Domain whose history to show.": "Domaine dont on veut l'historique.",
    "Number of scans.": "Nombre de scans.",
    "No saved scan for {domain}.": "Aucun scan enregistré pour {domain}.",
    "History — {domain}": "Historique — {domain}",
    "#": "N°",
    "Date": "Date",
    "Lang": "Langue",
    "Overall": "Global",
    "Compare the last two scans: new issues / fixed.": (
        "Compare les deux derniers scans : nouveaux problèmes / corrigés."
    ),
    "Domain whose last two scans to compare.": "Domaine dont on compare les deux derniers scans.",
    "At least two scans of {domain} are needed.": "Il faut au moins deux scans de {domain}.",
    "Grade: ": "Note : ",
    "New issues": "Nouveaux problèmes",
    "Worsened": "Aggravés",
    "Fixed": "Corrigés",
    "Improved": "Atténués",
    "No change between the two scans.": "Aucun changement entre les deux scans.",
    "{n} unchanged issue(s).": "{n} problème(s) inchangé(s).",
    "Not compared (missing or failed in one of the scans):": (
        "Non comparés (absents ou en échec dans l'un des scans) :"
    ),
    # ------------------------------------------------------------------ cœur
    "{host} resolves to a non-public address ({addresses}): connection refused": (
        "{host} résout vers une adresse non publique ({addresses}) : connexion refusée"
    ),
    "URL scheme not allowed: {scheme}": "Schéma d'URL non autorisé : {scheme}",
    "port {port} not allowed (80/443 only): {url}": (
        "port {port} non autorisé (80/443 uniquement) : {url}"
    ),
    "Unix sockets are not allowed": "Sockets Unix non autorisés",
    "Target resolves to a non-public IP address: web checks skipped": (
        "La cible pointe vers une adresse IP non publique : contrôles web non lancés"
    ),
    "{domain} points to a private, local or reserved address. To avoid reaching an internal "
    "network (SSRF), Sonde never connects to such addresses: the website was not contacted and "
    "is not graded. DNS-based email checks still ran.": (
        "{domain} pointe vers une adresse privée, locale ou réservée. Pour ne jamais atteindre "
        "un réseau interne (SSRF), Sonde ne se connecte jamais à ce type d'adresse : le site n'a "
        "pas été contacté et n'est pas noté. Les contrôles email (DNS) ont bien été réalisés."
    ),
    "If this domain is meant to be public, publish public A/AAAA records. Internal hosts are "
    "outside the scope of this tool.": (
        "Si ce domaine doit être public, publiez des enregistrements A/AAAA publics. Les hôtes "
        "internes sont hors du champ de cet outil."
    ),
    "timed out ({seconds} s)": "délai dépassé ({seconds} s)",
    "Check not completed: {name}": "Contrôle non réalisé : {name}",
    "This check could not complete; its result is not assessed.": (
        "Ce contrôle n'a pas pu aboutir ; le résultat n'est pas évalué."
    ),
    "invalid DKIM selector: {value}": "sélecteur DKIM invalide : {value}",
    "empty target": "cible vide",
    "empty or too long target": "cible vide ou trop longue",
    "spaces and control characters are not allowed": "espaces ou caractères de contrôle interdits",
    "unsupported scheme: {scheme}": "schéma non supporté : {scheme}",
    "credentials in the URL are not allowed": "identifiants dans l'URL interdits",
    "invalid port": "port invalide",
    "unsupported port: {port}": "port non supporté : {port}",
    "missing host": "hôte manquant",
    "forbidden character in the domain": "caractère interdit dans le domaine",
    "empty domain": "domaine vide",
    "an IP address is not a domain": "une adresse IP n'est pas un domaine",
    "invalid domain: {error}": "domaine invalide : {error}",
    "domain too long (>253)": "domaine trop long (>253)",
    "a full domain name is required (e.g. example.com)": (
        "un nom de domaine complet est requis (ex. exemple.fr)"
    ),
    "invalid domain label": "label de domaine invalide",
    "invalid TLD": "TLD invalide",
    "Database {path} uses an unknown schema (version {version}); it was created by a newer or "
    "pre-release version of Sonde. Move it aside or point SONDE_DB to another file.": (
        "La base {path} utilise un schéma inconnu (version {version}) : elle a été créée par une "
        "version plus récente ou une préversion de Sonde. Déplacez-la ou indiquez un autre "
        "fichier avec SONDE_DB."
    ),
    "{path} is not a Sonde database (or it is damaged). Move it aside or point SONDE_DB to "
    "another file.": (
        "{path} n'est pas une base Sonde (ou elle est endommagée). Déplacez-la ou indiquez un "
        "autre fichier avec SONDE_DB."
    ),
    # ------------------------------------------------------------------ rapport
    "Critical": "Critique",
    "Warning": "Attention",
    "Info": "Info",
    "OK": "OK",
    "Web security": "Sécurité web",
    "Email security": "Sécurité email",
    "{date} at {time}": "{date} à {time}",
    "PDF export unavailable. Install: pip install --require-hashes -r requirements-pdf.lock "
    "(and on macOS: brew install pango). HTML and JSON formats work without it.": (
        "Export PDF indisponible. Installez : pip install --require-hashes -r "
        "requirements-pdf.lock (et sur macOS : brew install pango). Les formats HTML et JSON "
        "fonctionnent sans."
    ),
    "Security audit — {domain}": "Audit de sécurité — {domain}",
    "Sonde · Security audit": "Sonde · Audit de sécurité",
    "Report of {date} · scan #{id}": "Rapport du {date} · scan n° {id}",
    "Passive mode": "Mode passif",
    "critical": "critique(s)",
    "warning": "attention",
    "passed": "conforme(s)",
    "info": "info(s)",
    "Partial results": "Résultats partiels",
    "{n} check(s) could not be completed (server unreachable, timeout, error or non-public "
    "address) and are not assessed: the grade is indicative.": (
        "{n} contrôle(s) n'ont pas pu être réalisés (serveur injoignable, délai dépassé, erreur "
        "ou adresse non publique) et ne sont donc pas évalués : la note est indicative."
    ),
    "Not graded": "Non noté",
    "Fix": "Correctif",
    "Technical evidence": "Constat technique",
    "Learn more": "Pour en savoir plus",
    "No check in this category.": "Aucun contrôle dans cette catégorie.",
    "Methodology": "Méthodologie",
    "This audit is passive: it only uses public information (HTTP headers, TLS certificate, "
    "DNS records, email configuration). No intrusion attempt was made. Each finding comes "
    "with a fix to apply.": (
        "Cet audit est passif : il n'utilise que des informations publiques (en-têtes HTTP, "
        "certificat TLS, enregistrements DNS, configuration de la messagerie). Aucune tentative "
        "d'intrusion n'a été effectuée. Chaque constat est accompagné d'un correctif à appliquer."
    ),
    "How the grade is computed": "Calcul de la note",
    "Each category (web, email) starts at 100 points: {crit} points are removed per critical "
    "finding, {warn} per warning, 0 for information. The penalty of a single check is capped "
    "at {cap} points so that one issue cannot sink the whole grade. The overall grade is the "
    "average of the audited categories.": (
        "Chaque catégorie (web, email) part de 100 points : {crit} points retirés par constat "
        "critique, {warn} par constat « attention », 0 pour les informations. La pénalité d'un "
        "même contrôle est plafonnée à {cap} points afin qu'un seul sujet ne fasse pas "
        "s'effondrer toute la note. La note globale est la moyenne des catégories auditées."
    ),
    "Limitations": "Limites",
    "This report is a snapshot as of {date}; the configuration may change afterwards.": (
        "Ce rapport est un instantané au {date} ; la configuration peut évoluer ensuite."
    ),
    "Only the home page is analyzed for headers, cookies and content: areas behind a login "
    "are not covered.": (
        "Seule la page d'accueil est analysée pour les en-têtes, cookies et contenus : les zones "
        "protégées par une connexion ne sont pas couvertes."
    ),
    "DKIM is looked up among the most common selector names; a custom selector may not be "
    "detected.": (
        "DKIM est recherché parmi les noms de sélecteurs les plus courants ; un sélecteur "
        "personnalisé peut ne pas être détecté."
    ),
    "This audit does not replace a full penetration test, nor a code or architecture review.": (
        "Cet audit ne remplace pas un test d'intrusion complet ni une revue de code ou "
        "d'architecture."
    ),
    "The absence of findings does not guarantee the absence of vulnerabilities.": (
        "L'absence de constat ne garantit pas l'absence de vulnérabilité."
    ),
    "Generated by Sonde {version}": "Généré par Sonde {version}",
    # ------------------------------------------------------------------ web.crtsh
    "… and {n} more": "… et {n} autre(s)",
    "Public subdomains (crt.sh)": "Sous-domaines publics (crt.sh)",
    "Public subdomains could not be listed.": "Les sous-domaines publics n'ont pas pu être listés.",
    "crt.sh unreachable": "crt.sh injoignable",
    "crt.sh unavailable": "crt.sh indisponible",
    "crt.sh response too large": "Réponse de crt.sh trop volumineuse",
    "The crt.sh answer exceeds {mb} MB and was not processed. The domain has too many "
    "certificates to list them this way.": (
        "La réponse de crt.sh dépasse {mb} Mo et n'a pas été traitée. Le domaine a trop de "
        "certificats pour les lister de cette façon."
    ),
    "response cut at {mb} MB": "réponse coupée à {mb} Mo",
    "No known public subdomain": "Aucun sous-domaine public connu",
    "No other name appears in public certificates.": (
        "Aucun autre nom n'apparaît dans les certificats publics."
    ),
    "Every name in a certificate is known to everyone: it is attack surface to keep up to "
    "date. These names are only listed; none of them was contacted.": (
        "Chaque nom présent dans un certificat est connu de tous : c'est une surface à tenir à "
        "jour. Ces noms sont seulement listés, aucun n'a été contacté."
    ),
    "Partial list: only the first {n} names returned by crt.sh were processed.": (
        "Liste partielle : seuls les {n} premiers noms renvoyés par crt.sh ont été traités."
    ),
    "Partial list: limited to {n} subdomains.": "Liste partielle : limitée à {n} sous-domaines.",
    "{n} subdomain(s) visible in public certificates": (
        "{n} sous-domaine(s) visible(s) dans les certificats publics"
    ),
    "Remove unused subdomains and keep the others up to date.": (
        "Supprimer les sous-domaines inutiles et garder les autres à jour."
    ),
    "{n} name(s) suggesting an admin or test service": (
        "{n} nom(s) évoquant un service d'administration ou de test"
    ),
    "Names like admin, vpn, jenkins or staging attract attackers. Their presence in a "
    "certificate does not prove they are reachable.": (
        "Des noms comme admin, vpn, jenkins ou staging attirent les attaquants. Leur présence "
        "dans un certificat ne prouve pas qu'ils soient accessibles."
    ),
    "Check that they are protected (VPN, IP allow-list, strong authentication) or remove them.": (
        "Vérifier qu'ils sont protégés (VPN, liste d'IP, authentification forte) ou les retirer."
    ),
    # ------------------------------------------------------------------ email.mta_sts
    "MTA-STS": "MTA-STS",
    "MTA-STS not configured": "MTA-STS non configuré",
    "MTA-STS requires servers that send you email to encrypt it in transit (TLS) and to "
    "verify your server, which prevents an attacker from downgrading or intercepting the "
    "connection. It is an additional protection, recommended but optional.": (
        "MTA-STS oblige les serveurs qui vous écrivent à chiffrer l'email en transit (TLS) et à "
        "vérifier votre serveur, ce qui empêche qu'un attaquant dégrade ou intercepte la "
        "connexion. C'est une protection complémentaire, recommandée mais optionnelle."
    ),
    "# + file https://mta-sts.{d}/.well-known/mta-sts.txt:": (
        "# + fichier https://mta-sts.{d}/.well-known/mta-sts.txt :"
    ),
    "MTA-STS: several TXT records": "MTA-STS : plusieurs enregistrements TXT",
    "Several “v=STSv1” records are published: senders then ignore MTA-STS.": (
        "Plusieurs enregistrements « v=STSv1 » sont publiés : MTA-STS est alors ignoré par les "
        "expéditeurs."
    ),
    "Keep a single TXT record on _mta-sts.{d}": "Ne garder qu'un seul enregistrement TXT sur _mta-sts.{d}",
    "MTA-STS: “id” missing": "MTA-STS : identifiant « id » manquant",
    "The TXT record must contain an “id” (changed on every policy update); without it the "
    "record is ignored.": (
        "L'enregistrement TXT doit contenir un « id » (change à chaque modification de la "
        "policy) ; sans lui il est ignoré."
    ),
    "policy too large (>64 KB)": "policy démesurée (>64 Ko)",
    "version: STSv1 missing": "version: STSv1 manquante",
    "invalid mode (enforce|testing|none)": "mode invalide (enforce|testing|none)",
    "no mx: line": "aucune ligne mx:",
    "max_age missing or invalid": "max_age manquant ou invalide",
    "MTA-STS: invalid policy": "MTA-STS : policy invalide",
    "The policy file is malformed, senders will ignore it: {problems}.": (
        "Le fichier de policy est mal formé, les expéditeurs l'ignoreront : {problems}."
    ),
    "Expected format:": "Format attendu :",
    "MTA-STS: “enforce” mode": "MTA-STS : mode « enforce »",
    "Compatible senders refuse to deliver your email without valid TLS to your MX servers.": (
        "Les expéditeurs compatibles refusent de livrer vos emails sans TLS valide vers vos "
        "serveurs MX."
    ),
    "MTA-STS: “testing” mode": "MTA-STS : mode « testing »",
    "The policy is published in test mode: anomalies are reported (if TLS-RPT is enabled) but "
    "no email is blocked.": (
        "La policy est publiée en mode test : les anomalies sont rapportées (si TLS-RPT est "
        "actif) mais aucun email n'est bloqué."
    ),
    "When reports are clean: mode: enforce (and change the TXT id).": (
        "Quand les rapports sont propres : mode: enforce (et changer l'id du TXT)."
    ),
    "MTA-STS: “none” mode": "MTA-STS : mode « none »",
    "The policy is published but disabled: no protection is applied.": (
        "La policy est publiée mais désactivée : aucune protection n'est appliquée."
    ),
    "mode: enforce (after a “testing” phase), then change the TXT id.": (
        "mode: enforce (après une phase « testing »), puis changer l'id du TXT."
    ),
    "MTA-STS: short max_age ({seconds} s)": "MTA-STS : max_age court ({seconds} s)",
    "Less than one day greatly limits the protection (senders forget the policy very "
    "quickly). Aim for at least one week.": (
        "Une durée de moins d'un jour limite fortement la protection (les expéditeurs oublient "
        "la policy très vite). Visez au moins une semaine."
    ),
    "MTA-STS: an MX is not covered by the policy": (
        "MTA-STS : un MX n'est pas couvert par la policy"
    ),
    "Some actual MX servers are not listed in the policy: in “enforce” mode, email to them "
    "will be REFUSED.": (
        "Certains serveurs MX réels ne figurent pas dans la policy : en mode « enforce », les "
        "emails vers eux seront REFUSÉS."
    ),
    "Some actual MX servers are not listed in the policy.": (
        "Certains serveurs MX réels ne figurent pas dans la policy."
    ),
    "Add to the policy:": "Ajouter dans la policy :",
    "MX not covered: {hosts}": "MX non couverts : {hosts}",
    "MTA-STS: policy unreachable": "MTA-STS : policy inaccessible",
    "The DNS record announces MTA-STS but the policy file cannot be retrieved (valid HTTPS "
    "required, no redirect): the protection cannot apply.": (
        "L'enregistrement DNS annonce MTA-STS mais le fichier de policy n'est pas récupérable "
        "(HTTPS valide requis, sans redirection) : la protection ne peut pas s'appliquer."
    ),
    "Serve {url} over HTTPS (valid certificate for mta-sts.<domain>), status 200, no redirect.": (
        "Servir {url} en HTTPS (certificat valide pour mta-sts.<domaine>), code 200, sans "
        "redirection."
    ),
    # ------------------------------------------------------------------ web.https
    "HTTPS redirect + HSTS": "Redirection HTTPS + HSTS",
    "HTTP: too many redirects": "HTTP : trop de redirections",
    "More than {n} redirects without reaching HTTPS.": (
        "Plus de {n} redirections sans atteindre HTTPS."
    ),
    "HTTP (port 80) does not respond": "HTTP (port 80) ne répond pas",
    "The site cannot be reached over http://. This is not a vulnerability, but a visitor "
    "typing the domain without “https://” will get an error instead of being redirected.": (
        "Le site n'est pas joignable en http://. Ce n'est pas une faille, mais un visiteur qui "
        "tape le domaine sans « https:// » verra une erreur au lieu d'être redirigé."
    ),
    "Open port 80 with a simple 301 redirect to HTTPS:": (
        "Ouvrir le port 80 avec une simple redirection 301 vers HTTPS :"
    ),
    "The site is served over unencrypted HTTP": "Le site est servi en HTTP non chiffré",
    "The http:// version of the site answers without redirecting to https://. Visitors can "
    "browse in clear text: passwords, forms and pages can be read and modified by a third "
    "party on the network.": (
        "La version http:// du site répond sans renvoyer vers https://. Les visiteurs peuvent "
        "naviguer en clair : mots de passe, formulaires et pages sont lisibles et modifiables "
        "par un tiers sur le réseau."
    ),
    "Temporary HTTPS redirect ({code})": "Redirection HTTPS temporaire ({code})",
    "The redirect to HTTPS works but uses a “temporary” status code. A permanent code (301 "
    "or 308) is better remembered by browsers and search engines.": (
        "La redirection vers HTTPS fonctionne mais utilise un code « temporaire ». Un code "
        "permanent (301 ou 308) est mieux mémorisé par les navigateurs et les moteurs de "
        "recherche."
    ),
    "Chain of {n} redirects before HTTPS": "Chaîne de {n} redirections avant HTTPS",
    "Several hops are needed before reaching HTTPS; each HTTP hop is a chance for "
    "interception. A single redirect is enough.": (
        "Plusieurs sauts sont nécessaires avant d'arriver en HTTPS ; chaque saut en HTTP est une "
        "occasion d'interception. Une seule redirection suffit."
    ),
    "HTTP → HTTPS redirect in place": "Redirection HTTP → HTTPS en place",
    "A visitor arriving over http:// is immediately sent to the encrypted version of the site.": (
        "Un visiteur arrivant en http:// est immédiatement renvoyé vers la version chiffrée du "
        "site."
    ),
    "Site unreachable over HTTPS": "Site injoignable en HTTPS",
    "The https:// version of the site does not respond: encrypted browsing is impossible.": (
        "La version https:// du site ne répond pas : impossible de naviguer de façon chiffrée."
    ),
    "Check that the server listens on port 443 with a valid certificate.": (
        "Vérifier que le serveur écoute sur le port 443 avec un certificat valide."
    ),
    "HTTPS redirects to HTTP": "HTTPS redirige vers HTTP",
    "The secure version of the site sends the visitor to the unencrypted one.": (
        "La version sécurisée du site renvoie le visiteur vers la version non chiffrée."
    ),
    "Remove the redirect to http://; serve the whole site over HTTPS.": (
        "Supprimer la redirection vers http:// ; servir tout le site en HTTPS."
    ),
    "HSTS missing": "HSTS absent",
    "Without HSTS, the browser tries http:// again on every visit typed by hand; an attacker "
    "on the network can intercept that first exchange before the redirect.": (
        "Sans HSTS, le navigateur retente une connexion http:// à chaque nouvelle visite tapée "
        "à la main ; un attaquant sur le réseau peut intercepter ce premier échange avant la "
        "redirection."
    ),
    "{url}: no Strict-Transport-Security header": "{url} : pas d'en-tête Strict-Transport-Security",
    "Invalid HSTS (max-age missing)": "HSTS invalide (max-age manquant)",
    "The HSTS header is present but has no duration: browsers ignore it.": (
        "L'en-tête HSTS est présent mais sans durée : les navigateurs l'ignorent."
    ),
    "HSTS disabled (max-age=0)": "HSTS désactivé (max-age=0)",
    "max-age=0 tells browsers to forget HSTS: no protection.": (
        "max-age=0 demande aux navigateurs d'oublier HSTS : aucune protection."
    ),
    "HSTS too short ({seconds} s)": "HSTS trop court ({seconds} s)",
    "The HSTS duration is under 6 months: the protection fades quickly between visits. "
    "Recommendation: at least 1 year.": (
        "La durée HSTS est inférieure à 6 mois : la protection s'efface vite entre deux visites. "
        "Recommandation : au moins 1 an."
    ),
    "Browsers that have already visited the site will refuse any unencrypted connection.": (
        "Les navigateurs qui ont déjà visité le site refuseront toute connexion non chiffrée."
    ),
    "Subdomains are not covered (includeSubDomains missing).": (
        "Les sous-domaines ne sont pas couverts (includeSubDomains absent)."
    ),
    "The site is a candidate for the browsers' preload list.": (
        "Le site est candidat à la liste de préchargement des navigateurs."
    ),
    "HSTS enabled (preload)": "HSTS actif (preload)",
    "HSTS enabled": "HSTS actif",
    "HSTS without includeSubDomains": "HSTS sans includeSubDomains",
    "Subdomains (www, api, …) do not benefit from HSTS. Add it if all subdomains are served "
    "over HTTPS.": (
        "Les sous-domaines (www, api, …) ne bénéficient pas de HSTS. À ajouter si tous les "
        "sous-domaines sont servis en HTTPS."
    ),
    # ------------------------------------------------------------------ web.headers
    "'unsafe-inline' allows scripts written in the page: XSS is no longer blocked": (
        "'unsafe-inline' autorise les scripts écrits dans la page : le XSS n'est plus bloqué"
    ),
    "'unsafe-eval' allows eval(): weakens XSS protection": (
        "'unsafe-eval' autorise eval() : affaiblit la protection XSS"
    ),
    "“*” allows scripts from any site": "« * » autorise les scripts de n'importe quel site",
    "“http:” allows unencrypted scripts": "« http: » autorise des scripts non chiffrés",
    "“https:” allows scripts from any HTTPS site": (
        "« https: » autorise les scripts de n'importe quel site en HTTPS"
    ),
    "“data:” allows injecting an inline script": "« data: » permet d'injecter un script en ligne",
    "neither script-src nor default-src: scripts are not restricted": (
        "ni script-src ni default-src : les scripts ne sont pas restreints"
    ),
    "Security headers": "En-têtes de sécurité",
    "CSP in “report-only” mode only": "CSP en mode « report-only » uniquement",
    "A CSP is defined but only in observation mode: nothing is blocked. It is a test step "
    "that should be completed.": (
        "Une politique CSP est définie mais seulement en observation : rien n'est bloqué. C'est "
        "une étape de test à faire aboutir."
    ),
    "Once reports are clean, rename the header to Content-Security-Policy.": (
        "Une fois les rapports propres, renommer l'en-tête en Content-Security-Policy."
    ),
    "Content-Security-Policy missing": "Content-Security-Policy absente",
    "The CSP tells the browser where the site may load scripts, styles and images from. "
    "Without it, an injection flaw (XSS) has free rein.": (
        "La CSP indique au navigateur d'où le site a le droit de charger scripts, styles et "
        "images. Sans elle, une faille d'injection (XSS) a le champ libre."
    ),
    "# adapt: list the CDNs/domains actually used": (
        "# à adapter : lister les CDN/domaines réellement utilisés"
    ),
    "Permissive CSP for scripts": "CSP permissive pour les scripts",
    "A CSP is present but its script rules largely cancel its protection: {issues}.": (
        "Une CSP est présente mais ses règles pour les scripts annulent largement sa "
        "protection : {issues}."
    ),
    "Remove 'unsafe-inline'/'unsafe-eval'/'*' from script-src; use nonces ('nonce-…') or "
    "hashes for inline scripts.": (
        "Retirer 'unsafe-inline'/'unsafe-eval'/'*' de script-src ; utiliser des nonces "
        "('nonce-…') ou des hachages pour les scripts en ligne."
    ),
    "Content-Security-Policy present and restrictive for scripts": (
        "Content-Security-Policy présente et restrictive pour les scripts"
    ),
    "The browser only runs explicitly allowed scripts.": (
        "Le navigateur n'exécute que les scripts explicitement autorisés."
    ),
    "CSP: object-src not restricted": "CSP : object-src non restreint",
    "Without “object-src 'none'” or default-src, plugins (Flash, Java…) can still be loaded.": (
        "Sans « object-src 'none' » ni default-src, les plugins (Flash, Java…) restent chargeables."
    ),
    "Add “object-src 'none'” to the CSP.": "Ajouter « object-src 'none' » à la CSP.",
    "frame-ancestors too permissive": "frame-ancestors trop permissif",
    "The CSP allows any site to display your pages in a frame (“clickjacking”: a visitor "
    "clicks on your site without knowing it).": (
        "La CSP autorise n'importe quel site à afficher vos pages dans un cadre (« clickjacking » "
        ": un visiteur clique sur votre site sans le savoir)."
    ),
    "frame-ancestors 'self' (or 'none')": "frame-ancestors 'self' (ou 'none')",
    "Clickjacking protection (frame-ancestors)": "Protection anti-clickjacking (frame-ancestors)",
    "Only allowed sites can display your pages in a frame.": (
        "Seuls les sites autorisés peuvent afficher vos pages dans un cadre."
    ),
    "Clickjacking protection (X-Frame-Options: {value})": (
        "Protection anti-clickjacking (X-Frame-Options: {value})"
    ),
    "Your pages cannot be embedded in a frame by another site.": (
        "Vos pages ne peuvent pas être intégrées dans un cadre par un autre site."
    ),
    "Obsolete X-Frame-Options: ALLOW-FROM": "X-Frame-Options: ALLOW-FROM obsolète",
    "Browsers no longer understand this syntax: in practice there is no protection.": (
        "Cette syntaxe n'est plus comprise par les navigateurs : la protection est absente en "
        "pratique."
    ),
    "Replace with the CSP directive: frame-ancestors 'self' https://partner.tld": (
        "Remplacer par la directive CSP : frame-ancestors 'self' https://partenaire.tld"
    ),
    "No clickjacking protection": "Aucune protection anti-clickjacking",
    "Neither X-Frame-Options nor frame-ancestors: any site can display yours in an invisible "
    "frame and hijack your visitors' clicks.": (
        "Ni X-Frame-Options ni frame-ancestors : n'importe quel site peut afficher le vôtre dans "
        "un cadre invisible et détourner les clics de vos visiteurs."
    ),
    "# or, in the CSP: frame-ancestors 'self'": "# ou, dans la CSP : frame-ancestors 'self'",
    "The browser respects the declared file type instead of guessing it.": (
        "Le navigateur respecte le type annoncé des fichiers au lieu de le deviner."
    ),
    "X-Content-Type-Options missing": "X-Content-Type-Options absent",
    "Without “nosniff”, the browser may interpret a harmless file (image, text) as a script, "
    "which makes some attacks easier.": (
        "Sans « nosniff », le navigateur peut interpréter un fichier anodin (image, texte) comme "
        "du script, ce qui facilite certaines attaques."
    ),
    "(missing)": "(absent)",
    "The full address of visited pages is not sent to third-party sites.": (
        "L'adresse complète des pages visitées n'est pas transmise aux sites tiers."
    ),
    "Permissive Referrer-Policy ({value})": "Referrer-Policy permissive ({value})",
    "The full URL of pages (including parameters) is sent to the third-party sites your links "
    "point to.": (
        "L'URL complète des pages (y compris paramètres) est envoyée aux sites tiers vers "
        "lesquels pointent vos liens."
    ),
    "Referrer-Policy missing": "Referrer-Policy absente",
    "Browsers apply a reasonable default, but making it explicit prevents URL leaks to "
    "third-party sites.": (
        "Les navigateurs appliquent un défaut raisonnable, mais l'expliciter évite les fuites "
        "d'URL vers des sites tiers."
    ),
    "Permissions-Policy present": "Permissions-Policy présente",
    "The site restricts sensitive browser features (camera, microphone, geolocation…) "
    "available to the page and its frames.": (
        "Le site limite les fonctionnalités sensibles du navigateur (caméra, micro, "
        "géolocalisation…) utilisables par la page et ses cadres."
    ),
    "Permissions-Policy missing": "Permissions-Policy absente",
    "Optional: this header explicitly forbids use of the camera, microphone or geolocation by "
    "the page and the third-party content it embeds.": (
        "Optionnel : cet en-tête interdit explicitement l'usage de la caméra, du micro ou de la "
        "géolocalisation par la page et les contenus tiers qu'elle intègre."
    ),
    "Cross-origin isolation (COOP + CORP)": "Isolation cross-origin (COOP + CORP)",
    "The site is isolated from windows and resources of other origins.": (
        "Le site est isolé des fenêtres et ressources d'autres origines."
    ),
    "COOP / CORP missing or partial": "COOP / CORP absents ou partiels",
    "Optional: these headers isolate the site from other tabs and prevent other sites from "
    "embedding your resources. Mostly useful for applications handling sensitive data.": (
        "Optionnel : ces en-têtes isolent le site des autres onglets et empêchent d'autres sites "
        "d'intégrer vos ressources. Utile surtout pour les applications manipulant des données "
        "sensibles."
    ),
    "Obsolete X-XSS-Protection": "X-XSS-Protection obsolète",
    "This filter was removed from browsers and could itself create flaws. It is useless; the "
    "CSP replaces it.": (
        "Ce filtre a été retiré des navigateurs et pouvait lui-même créer des failles. Il est "
        "inutile ; la CSP le remplace."
    ),
    "# or simply remove the header": "# ou simplement retirer l'en-tête",
    # ------------------------------------------------------------------ web.cert
    "TLS certificate": "Certificat TLS",
    "Renew the certificate (e.g. Let's Encrypt, free and automatable):": (
        "Renouveler le certificat (ex. Let's Encrypt, gratuit et automatisable) :"
    ),
    "# or at your hosting provider: enable automatic renewal": (
        "# ou chez votre hébergeur : activer le renouvellement automatique"
    ),
    "No TLS certificate presented": "Aucun certificat TLS présenté",
    "The server did not provide a certificate: encrypted connection is impossible.": (
        "Le serveur n'a pas fourni de certificat : la connexion chiffrée est impossible."
    ),
    "Subject: {subject}\nIssuer: {issuer}\nValid from {start} to {end} ({days} days left)"
    "\nSAN: {sans}": (
        "Sujet : {subject}\nÉmetteur : {issuer}\nValide du {start} au {end} ({days} j restants)"
        "\nSAN : {sans}"
    ),
    "Certificate expired {n} day(s) ago": "Certificat expiré depuis {n} jour(s)",
    "The certificate is no longer valid: browsers show a red warning page and most visitors "
    "turn back.": (
        "Le certificat n'est plus valable : les navigateurs affichent une page d'alerte rouge "
        "et la plupart des visiteurs font demi-tour."
    ),
    "Certificate not yet valid": "Certificat pas encore valide",
    "The validity start date is in the future: browsers reject it.": (
        "La date de début de validité est dans le futur : les navigateurs le refusent."
    ),
    "Check the server clock and reissue the certificate.": (
        "Vérifier l'horloge du serveur et réémettre le certificat."
    ),
    "Certificate expires in {n} day(s)": "Certificat expire dans {n} jour(s)",
    "The certificate is about to expire. After that, the site will show a security warning "
    "to every visitor.": (
        "Le certificat expire de façon imminente. Passé ce délai, le site affichera une alerte "
        "de sécurité à tous les visiteurs."
    ),
    "Certificate expires in {n} days": "Certificat expire dans {n} jours",
    "The certificate expires soon. If renewal is not automated, schedule it now.": (
        "Le certificat expire bientôt. Si le renouvellement n'est pas automatisé, planifiez-le "
        "maintenant."
    ),
    "The certificate does not cover this domain": "Le certificat ne couvre pas ce domaine",
    "The certificate presented was not issued for “{d}”: browsers show a “wrong name” error.": (
        "Le certificat présenté n'est pas émis pour « {d} » : les navigateurs affichent une "
        "erreur « nom incorrect »."
    ),
    "Reissue a certificate including {d} in its alternative names (SAN).": (
        "Réémettre un certificat incluant {d} dans ses noms alternatifs (SAN)."
    ),
    "The certificate does not cover www.{d}": "Le certificat ne couvre pas www.{d}",
    "Visitors typing “www.” will see a certificate error. Ignore this if the www subdomain "
    "is not used.": (
        "Si des visiteurs tapent « www. », ils verront une erreur de certificat. À ignorer si "
        "le sous-domaine www n'est pas utilisé."
    ),
    "Add www.{d} to the certificate SANs.": "Ajouter www.{d} aux SAN du certificat.",
    "Untrusted certificate (invalid chain of trust)": (
        "Certificat non reconnu (chaîne de confiance invalide)"
    ),
    "The certificate is not validated by trusted authorities: self-signed, unknown authority "
    "or missing intermediate certificate. Browsers show a security warning.": (
        "Le certificat n'est pas validé par les autorités de confiance : auto-signé, autorité "
        "inconnue ou certificat intermédiaire manquant. Les navigateurs affichent une alerte de "
        "sécurité."
    ),
    "Install the full chain (certificate + intermediates, “fullchain.pem”) provided by the "
    "certificate authority.": (
        "Installer la chaîne complète (certificat + intermédiaires, « fullchain.pem ») fournie "
        "par l'autorité de certification."
    ),
    "Error: {error}": "Erreur : {error}",
    "Weak RSA key ({bits} bits)": "Clé RSA faible ({bits} bits)",
    "A key under 2048 bits is considered insufficient.": (
        "Une clé de moins de 2048 bits est considérée comme insuffisante."
    ),
    "Reissue the certificate with an RSA 2048+ or ECDSA P-256 key.": (
        "Réémettre le certificat avec une clé RSA 2048+ ou ECDSA P-256."
    ),
    "Obsolete {algo} signature": "Signature {algo} obsolète",
    "The certificate's signature algorithm is broken: modern browsers reject it.": (
        "L'algorithme de signature du certificat est cassé : les navigateurs modernes le rejettent."
    ),
    "Reissue the certificate (SHA-256).": "Réémettre le certificat (SHA-256).",
    "Valid certificate ({n} days left)": "Certificat valide ({n} jours restants)",
    "Certificate issued by {issuer}, trusted by browsers, covering the domain. Key: {key}.": (
        "Certificat émis par {issuer}, reconnu par les navigateurs, couvrant le domaine. "
        "Clé : {key}."
    ),
    "Certificate issued by {issuer}, trusted by browsers, covering the domain.": (
        "Certificat émis par {issuer}, reconnu par les navigateurs, couvrant le domaine."
    ),
    "RSA {bits} bits": "RSA {bits} bits",
    # ------------------------------------------------------------------ web.tls_versions
    "TLS versions": "Versions TLS",
    "no TLS version could be tested from this machine": (
        "aucune version TLS n'a pu être testée depuis cette machine"
    ),
    "accepted": "acceptée",
    "refused": "refusée",
    "not testable": "non testable",
    "Negotiated by default: {protocol}": "Négocié par défaut : {protocol}",
    "Only obsolete TLS versions are accepted": "Seules des versions TLS obsolètes sont acceptées",
    "The server accepts neither TLS 1.2 nor TLS 1.3. Recent browsers refuse the connection, "
    "and old versions have known weaknesses.": (
        "Le serveur n'accepte ni TLS 1.2 ni TLS 1.3. Les navigateurs récents refusent la "
        "connexion, et les anciennes versions ont des faiblesses connues."
    ),
    "Obsolete versions accepted: {versions}": "Versions obsolètes acceptées : {versions}",
    "TLS 1.0 and 1.1 have been deprecated since 2021 (RFC 8996): they rely on weakened "
    "algorithms. Leaving them enabled lets an attacker force a downgraded connection.": (
        "TLS 1.0 et 1.1 sont retirés depuis 2021 (RFC 8996) : ils reposent sur des algorithmes "
        "affaiblis. Les laisser actifs permet à un attaquant de forcer une connexion dégradée."
    ),
    "TLS 1.3 not offered": "TLS 1.3 non proposé",
    "Only TLS 1.2 is accepted. That is safe, but TLS 1.3 is faster and removes fragile options.": (
        "Seul TLS 1.2 est accepté. C'est sûr, mais TLS 1.3 est plus rapide et supprime les "
        "options fragiles."
    ),
    "TLS versions: {versions}": "Versions TLS : {versions}",
    "Only modern TLS versions are accepted.": "Seules des versions modernes de TLS sont acceptées.",
    "TLS versions not determined": "Versions TLS non déterminées",
    "No version could be confirmed from this machine.": (
        "Aucune version n'a pu être confirmée depuis cette machine."
    ),
    "Not testable locally: {versions}": "Non testable localement : {versions}",
    "This machine's TLS library cannot test these versions.": (
        "La bibliothèque TLS de cette machine ne permet pas de tester ces versions."
    ),
    # ------------------------------------------------------------------ web.cookies
    "Cookies": "Cookies",
    "No cookie set on the home page": "Aucun cookie posé sur la page d'accueil",
    "The home page sets no cookie; nothing to secure here. Session cookies often appear after "
    "login, which is not tested.": (
        "La page d'accueil ne dépose pas de cookie ; rien à sécuriser ici. Les cookies de "
        "session apparaissent souvent après connexion, non testée."
    ),
    "Secure missing": "Secure manquant",
    "the cookie may be sent in clear text over http:// and intercepted": (
        "le cookie peut être envoyé en clair sur http:// et intercepté"
    ),
    "HttpOnly missing": "HttpOnly manquant",
    "an injected script (XSS) can read the cookie and steal the session": (
        "un script injecté (XSS) peut lire le cookie et voler la session"
    ),
    "SameSite not specified": "SameSite non précisé",
    "browsers apply “Lax” by default, better make it explicit": (
        "les navigateurs appliquent « Lax » par défaut, mieux vaut l'expliciter"
    ),
    "SameSite=None without Secure": "SameSite=None sans Secure",
    "combination rejected by modern browsers": "combinaison rejetée par les navigateurs modernes",
    "Empty SameSite": "SameSite vide",
    "value ignored by browsers": "valeur ignorée par les navigateurs",
    "Cookie “{name}” properly protected": "Cookie « {name} » correctement protégé",
    "The cookie is marked Secure, HttpOnly and SameSite.": (
        "Le cookie est marqué Secure, HttpOnly et SameSite."
    ),
    "Cookie “{name}”: {labels}": "Cookie « {name} » : {labels}",
    "The cookie “{name}” lacks some protection attributes ({explain}). For a mere preference "
    "cookie the impact is low; for a session cookie it matters.": (
        "Le cookie « {name} » n'a pas tous les attributs de protection ({explain}). Si c'est un "
        "simple cookie de préférence, l'impact est faible ; si c'est une session, c'est "
        "important."
    ),
    # ------------------------------------------------------------------ web.leaks
    "header {name}": "en-tête {name}",
    "“{hint}” found in the page": "présence de « {hint} » dans la page",
    "Information leaks": "Fuites d'information",
    "?ver= parameter on a /wp-includes/ file": "paramètre ?ver= sur un fichier /wp-includes/",
    "No obvious information leak": "Pas de fuite d'information évidente",
    "Neither the page nor the headers reveal the technology or versions used.": (
        "Ni la page ni les en-têtes ne révèlent la technologie ou les versions utilisées."
    ),
    "Server version exposed ({header})": "Version du serveur exposée ({header})",
    "The {header} header reveals the exact software version. An attacker immediately knows "
    "which known flaws to try.": (
        "L'en-tête {header} révèle la version exacte du logiciel. Un attaquant sait "
        "immédiatement quelles failles connues essayer."
    ),
    "Technology disclosed ({header})": "Technologie annoncée ({header})",
    "The {header} header names the software used, without version. Minor, but easy to hide.": (
        "L'en-tête {header} indique le logiciel utilisé, sans version. Peu grave, mais "
        "facilement masquable."
    ),
    "{cms} {version}: version visible": "{cms} {version} : version visible",
    "The exact version of {cms} is publicly readable. If it is not up to date, the "
    "corresponding flaws are known to everyone.": (
        "La version exacte de {cms} est lisible publiquement. Si elle n'est pas à jour, les "
        "failles correspondantes sont connues de tous."
    ),
    "# WordPress (theme functions.php)": "# WordPress (functions.php du thème)",
    "Disable the generator tag in the {cms} configuration and keep the CMS up to date.": (
        "Désactiver la balise generator dans la configuration de {cms} et maintenir le CMS à jour."
    ),
    "CMS identified: {cms}": "CMS identifié : {cms}",
    "The site uses {cms}. This is not a vulnerability, but it must be kept up to date (core, "
    "themes, plugins).": (
        "Le site utilise {cms}. Ce n'est pas une faille, mais il faut le maintenir à jour "
        "(cœur, thèmes, extensions)."
    ),
    "WordPress: /readme.html accessible (version {version})": (
        "WordPress : /readme.html accessible (version {version})"
    ),
    "WordPress: /readme.html accessible": "WordPress : /readme.html accessible",
    "The readme.html file shipped with WordPress is public; it confirms the CMS and often its "
    "version.": (
        "Le fichier readme.html livré avec WordPress est public ; il confirme le CMS et souvent "
        "sa version."
    ),
    "Delete readme.html (and license.txt) on every update, or:": (
        "Supprimer readme.html (et license.txt) à chaque mise à jour, ou :"
    ),
    "WordPress: public REST API (/wp-json/)": "WordPress : API REST publique (/wp-json/)",
    "The REST API is open without authentication. That is normal for WordPress, but "
    "/wp-json/wp/v2/users often lists author logins, useful for a password attack.": (
        "L'API REST est ouverte sans authentification. Elle est normale pour WordPress, mais "
        "/wp-json/wp/v2/users permet souvent de lister les identifiants des auteurs, utiles pour "
        "une attaque par mot de passe."
    ),
    "Restrict /wp-json/wp/v2/users to logged-in users (security plugin or rest_endpoints "
    "filter) and enable login attempt limiting.": (
        "Restreindre /wp-json/wp/v2/users aux utilisateurs connectés (extension de sécurité ou "
        "filtre rest_endpoints) et activer la limitation des tentatives de connexion."
    ),
    "{n} namespaces": "{n} espaces de noms",
    # ------------------------------------------------------------------ web.mixed_content
    "Mixed content": "Contenu mixte",
    "No mixed content on the home page": "Pas de contenu mixte sur la page d'accueil",
    "All resources of the page are loaded over HTTPS.": (
        "Toutes les ressources de la page sont chargées en HTTPS."
    ),
    "Replace http:// URLs with https:// (or relative URLs) in the code and the database.": (
        "Remplacer les URL http:// par https:// (ou des URL relatives) dans le code et la base "
        "de données."
    ),
    "# Safety net (automatic rewriting by the browser):": (
        "# Filet de sécurité (réécriture automatique par le navigateur) :"
    ),
    "Form submitted over unencrypted HTTP": "Formulaire envoyé en HTTP non chiffré",
    "A form on the page sends its data to an http:// address: what the visitor types travels "
    "in clear text.": (
        "Un formulaire de la page envoie ses données vers une adresse http:// : ce que saisit le "
        "visiteur circule en clair."
    ),
    "Active mixed content ({n} resource(s))": "Contenu mixte actif ({n} ressource(s))",
    "Scripts, styles or frames are referenced over http://. Browsers block them: broken "
    "features, and a sign of an incomplete HTTPS migration.": (
        "Des scripts, styles ou cadres sont référencés en http://. Les navigateurs les "
        "bloquent : fonctionnalités cassées, et signe d'une migration HTTPS incomplète."
    ),
    "Passive mixed content ({n} resource(s))": "Contenu mixte passif ({n} ressource(s))",
    "Images or media are loaded over http://. The browser shows a “not secure” warning and "
    "this content can be replaced in transit.": (
        "Des images ou médias sont chargés en http://. Le navigateur affiche un avertissement "
        "« non sécurisé » et ces contenus peuvent être remplacés en transit."
    ),
    # ------------------------------------------------------------------ web.security_txt
    "security.txt": "security.txt",
    "security.txt missing": "security.txt absent",
    "This standard file says whom to report a security flaw to. Without it, a researcher who "
    "finds a problem does not know whom to warn.": (
        "Ce fichier standard indique à qui signaler une faille de sécurité. Sans lui, un "
        "chercheur qui découvre un problème ne sait pas qui prévenir."
    ),
    "(content without Contact field)": "(contenu sans champ Contact)",
    "Contact field missing (required)": "champ Contact manquant (obligatoire)",
    "Expires field missing (required)": "champ Expires manquant (obligatoire)",
    "Expires unreadable (ISO 8601 format expected)": "Expires illisible (format ISO 8601 attendu)",
    "file expired since {date}": "fichier expiré depuis le {date}",
    "several Expires fields": "plusieurs champs Expires",
    "Contact “{value}” must be a URI (mailto:, https:, tel:)": (
        "Contact « {value} » doit être une URI (mailto:, https:, tel:)"
    ),
    "Invalid security.txt": "security.txt invalide",
    "The file exists but is not compliant: {problems}.": (
        "Le fichier existe mais n'est pas conforme : {problems}."
    ),
    "security.txt present and valid": "security.txt présent et valide",
    "A security contact is published for reporting vulnerabilities.": (
        "Un point de contact sécurité est publié pour signaler une vulnérabilité."
    ),
    # ------------------------------------------------------------------ email.mx
    "MX (incoming email)": "MX (réception des emails)",
    "No MX record": "Aucun enregistrement MX",
    "This domain declares no server to receive email. That is normal if it is not used for "
    "email; it must still be protected against spoofing (SPF “-all” and DMARC “reject”).": (
        "Ce domaine ne déclare aucun serveur pour recevoir des emails. C'est normal s'il ne sert "
        "pas à la messagerie ; dans ce cas, il doit quand même être protégé contre l'usurpation "
        "(SPF « -all » et DMARC « reject »)."
    ),
    "“null MX”: explicitly declares that no email is accepted": (
        "« null MX » : déclare explicitement qu'aucun email n'est accepté"
    ),
    "Domain configured to receive no email (null MX)": (
        "Domaine configuré pour ne pas recevoir d'email (null MX)"
    ),
    "The domain explicitly states that it accepts no email. Good practice for a domain that "
    "neither sends nor receives messages.": (
        "Le domaine indique explicitement qu'il n'accepte aucun email. Bonne pratique pour un "
        "domaine qui n'envoie ni ne reçoit de messages."
    ),
    "Mail servers (MX) present — provider: {provider}": (
        "Serveurs de messagerie (MX) présents — fournisseur : {provider}"
    ),
    "Mail servers (MX) present": "Serveurs de messagerie (MX) présents",
    "The domain can receive email, via {provider}.": (
        "Le domaine sait recevoir des emails, via {provider}."
    ),
    "The domain can receive email; the provider could not be identified.": (
        "Le domaine sait recevoir des emails ; le fournisseur n'a pas pu être identifié."
    ),
    "A single MX server is declared: during an outage, email depends on senders retrying "
    "(acceptable with large providers that handle redundancy internally).": (
        "Un seul serveur MX est déclaré : en cas de panne, les emails dépendent du réessai des "
        "expéditeurs (acceptable chez les grands fournisseurs qui gèrent la redondance en "
        "interne)."
    ),
    # ------------------------------------------------------------------ email.spf
    "SPF loop detected via “{domain}”": "boucle SPF détectée via « {domain} »",
    "{label}:{domain} points to no SPF record": (
        "{label}:{domain} ne pointe vers aucun enregistrement SPF"
    ),
    "{label}:{domain} publishes several SPF records": (
        "{label}:{domain} publie plusieurs enregistrements SPF"
    ),
    "SPF": "SPF",
    "SPF missing": "SPF absent",
    "No SPF rule says which servers may send email on behalf of this domain. Anyone can "
    "therefore impersonate you, and your real email may end up in spam.": (
        "Aucune règle SPF n'indique quels serveurs ont le droit d'envoyer des emails au nom de "
        "ce domaine. N'importe qui peut donc se faire passer pour vous, et vos vrais emails "
        "risquent d'être classés en spam."
    ),
    "; replace the include with your provider's (e.g. Google: include:_spf.google.com; "
    "Microsoft 365: include:spf.protection.outlook.com)": (
        "; remplacez l'include par celui de votre fournisseur (ex. Google : "
        "include:_spf.google.com ; Microsoft 365 : include:spf.protection.outlook.com)"
    ),
    "SPF missing (domain without email)": "SPF absent (domaine sans messagerie)",
    "The domain receives no email but does not forbid sending on its behalf: it can be used "
    "for spoofing.": (
        "Le domaine ne reçoit pas d'emails mais n'interdit pas qu'on envoie en son nom : il peut "
        "servir à de l'usurpation."
    ),
    "Several SPF records": "Plusieurs enregistrements SPF",
    "The domain publishes several SPF rules. In that case receiving servers ignore SPF "
    "entirely (“permerror”): the protection does not work.": (
        "Le domaine publie plusieurs règles SPF. Dans ce cas, les serveurs destinataires "
        "ignorent SPF complètement (erreur « permerror ») : la protection est inopérante."
    ),
    "Merge into ONE SINGLE TXT record starting with v=spf1 (group the “include:” terms and "
    "keep a single “-all” at the end).": (
        "Fusionner en UN SEUL enregistrement TXT commençant par v=spf1 (regrouper les "
        "« include: » et garder un seul « -all » à la fin)."
    ),
    "SPF: invalid reference": "SPF : référence invalide",
    "An SPF rule is broken ({issue}). A single invalid include makes the whole record "
    "unusable (“permerror”).": (
        "Une règle SPF est cassée ({issue}). Un seul include invalide rend tout l'enregistrement "
        "inutilisable (erreur « permerror »)."
    ),
    "Fix or remove the faulty reference in the SPF record.": (
        "Corriger ou retirer la référence fautive dans l'enregistrement SPF."
    ),
    "SPF: deprecated “ptr” mechanism": "SPF : mécanisme « ptr » déprécié",
    "The standard discourages the “ptr” mechanism: it is slow, unreliable and costs DNS lookups.": (
        "Le mécanisme « ptr » est déconseillé par la norme : il est lent, peu fiable et coûte "
        "des requêtes DNS."
    ),
    "Replace “ptr” with explicit “ip4:”, “ip6:” or “include:”.": (
        "Remplacer « ptr » par des « ip4: », « ip6: » ou « include: » explicites."
    ),
    "SPF: “+all” allows everyone": "SPF : « +all » autorise tout le monde",
    "The rule ends with “+all” (or a bare “all”): it allows any server on the internet to "
    "send email on your behalf. That is worse than having no SPF.": (
        "La règle se termine par « +all » (ou « all » seul) : elle autorise n'importe quel "
        "serveur d'internet à envoyer des emails en votre nom. C'est pire que l'absence de SPF."
    ),
    "SPF: neutral “?all”": "SPF : « ?all » neutre",
    "The rule ends with “?all”: receiving servers must draw no conclusion. Spoofed email is "
    "therefore not blocked.": (
        "La règle se termine par « ?all » : les serveurs destinataires ne doivent rien conclure. "
        "Les emails usurpés ne sont donc pas bloqués."
    ),
    "SPF: “~all” (soft fail)": "SPF : « ~all » (échec « mou »)",
    "The rule ends with “~all”: unauthorized email is only marked suspicious, not rejected. "
    "Acceptable while testing, but the protection is partial.": (
        "La règle se termine par « ~all » : les emails non autorisés sont seulement marqués "
        "suspects, pas rejetés. Acceptable en phase de test, mais la protection reste partielle."
    ),
    "; once DMARC is in place and legitimate senders are validated": (
        "; une fois DMARC en place et les expéditeurs légitimes validés"
    ),
    "SPF: strict policy (“-all”)": "SPF : politique stricte (« -all »)",
    "Only the listed servers may send email for this domain; the others are rejected.": (
        "Seuls les serveurs listés peuvent envoyer des emails pour ce domaine ; les autres sont "
        "rejetés."
    ),
    "SPF: no final “all”": "SPF : aucun « all » final",
    "The record ends with neither “-all” nor “~all”: without an explicit conclusion, any "
    "unlisted server is treated as neutral.": (
        "L'enregistrement ne se termine ni par « -all » ni par « ~all » : sans conclusion "
        "explicite, tout serveur non listé est traité comme neutre."
    ),
    "SPF: {n} DNS lookups (limit: {limit})": "SPF : {n} requêtes DNS (limite : {limit})",
    "The standard limits SPF to 10 DNS lookups (include, a, mx, exists, redirect). Beyond "
    "that, receivers reject the rule (“permerror”) and SPF protects nothing anymore, "
    "including your legitimate email.": (
        "La norme limite SPF à 10 requêtes DNS (include, a, mx, exists, redirect). Au-delà, les "
        "destinataires rejettent la règle (« permerror ») et SPF ne protège plus rien, y compris "
        "pour vos emails légitimes."
    ),
    "Remove useless “include:” terms, replace “a”/“mx” with “ip4:”/“ip6:”, or “flatten” SPF "
    "with a dedicated service.": (
        "Réduire les « include: » inutiles, remplacer des « a »/« mx » par des « ip4: »/« ip6: », "
        "ou « aplatir » SPF avec un service dédié."
    ),
    "SPF: {n}/{limit} DNS lookups": "SPF : {n}/{limit} requêtes DNS",
    "The number of DNS lookups triggered by SPF is within the limit of 10.": (
        "Le nombre de requêtes DNS déclenchées par SPF respecte la limite de 10."
    ),
    "Careful, it is close to the limit.": "Attention, on s'approche de la limite.",
    # ------------------------------------------------------------------ email.dkim
    "DKIM": "DKIM",
    "selectors tried: {names}": "sélecteurs testés : {names}",
    "DKIM: selector “{selector}” not found": "DKIM : sélecteur « {selector} » introuvable",
    "No DKIM key is published for the given selector. Without a valid DKIM signature, email "
    "is easier to spoof or lands in spam.": (
        "Aucune clé DKIM n'est publiée pour le sélecteur indiqué. Sans signature DKIM valable, "
        "les emails sont plus facilement usurpés ou classés en spam."
    ),
    "Publish the key provided by your sending service:": (
        "Publier la clé fournie par votre service d'envoi :"
    ),
    "DKIM: no key found (common selectors)": "DKIM : aucune clé trouvée (sélecteurs courants)",
    "No DKIM key was found among the usual selector names. This does not prove there is no "
    "DKIM: the selector may have a custom name. Check the header of a received email (field "
    "“DKIM-Signature: … s=NAME”) then run again with --dkim-selector.": (
        "Aucune clé DKIM n'a été trouvée parmi les noms de sélecteurs usuels. Cela ne prouve pas "
        "qu'il n'y a pas de DKIM : le sélecteur peut avoir un nom personnalisé. Vérifiez avec "
        "l'en-tête d'un email reçu (champ « DKIM-Signature: … s=NOM ») puis relancez avec "
        "--dkim-selector."
    ),
    "sonde-passif scan <domain> --dkim-selector NAME": (
        "sonde-passif scan <domaine> --dkim-selector NOM"
    ),
    "DKIM: {n} revoked selectors (empty key)": "DKIM : {n} sélecteurs révoqués (clé vide)",
    "These selectors exist but their key is empty: they were deliberately disabled. No risk, "
    "provided they are no longer used.": (
        "Ces sélecteurs existent mais leur clé est vide : ils ont été volontairement désactivés. "
        "Aucun risque, à condition qu'ils n'aient plus d'usage."
    ),
    "revoked selectors: {names}": "sélecteurs révoqués : {names}",
    "DKIM “{selector}”: revoked key": "DKIM « {selector} » : clé révoquée",
    "This selector exists but its key is empty: it was deliberately disabled. No risk, "
    "provided it is no longer used.": (
        "Ce sélecteur existe mais sa clé est vide : il a été volontairement désactivé. Aucun "
        "risque, à condition qu'il n'ait plus d'usage."
    ),
    "DKIM “{selector}”: unreadable key": "DKIM « {selector} » : clé illisible",
    "The published public key is malformed: signatures cannot be verified. Often caused by a "
    "truncated copy-paste.": (
        "La clé publique publiée est mal formée : les signatures ne pourront pas être vérifiées. "
        "Souvent causé par un copier-coller tronqué."
    ),
    "Publish the key again exactly as provided by your sending service (TXT strings longer "
    "than 255 characters must be split).": (
        "Republier la clé exactement telle que fournie par votre service d'envoi (attention aux "
        "chaînes TXT de plus de 255 caractères à découper)."
    ),
    "DKIM “{selector}”: Ed25519 key": "DKIM « {selector} » : clé Ed25519",
    "Modern, robust key. Also keep an RSA 2048 key for receivers that do not support Ed25519.": (
        "Clé moderne, robuste. Pensez à garder aussi une clé RSA 2048 pour les destinataires qui "
        "ne gèrent pas Ed25519."
    ),
    "DKIM “{selector}”: key type not assessed": "DKIM « {selector} » : type de clé non évalué",
    "A DKIM key is present but Sonde does not analyze its type.": (
        "Une clé DKIM est présente mais son type n'est pas analysé par Sonde."
    ),
    "DKIM “{selector}”: RSA key too weak ({bits} bits)": (
        "DKIM « {selector} » : clé RSA trop faible ({bits} bits)"
    ),
    "A key under 1024 bits can be broken with modest means: an attacker could forge signed "
    "email on behalf of the domain.": (
        "Une clé de moins de 1024 bits peut être cassée avec des moyens modestes : un attaquant "
        "pourrait fabriquer de faux emails signés au nom du domaine."
    ),
    "Generate a new 2048-bit RSA key (from your email provider) and publish the new TXT "
    "record; remove the old one after the switch.": (
        "Générer une nouvelle clé RSA 2048 bits (depuis votre fournisseur de messagerie) et "
        "publier le nouvel enregistrement TXT ; retirer l'ancien après bascule."
    ),
    "size: {bits} bits": "taille : {bits} bits",
    "DKIM “{selector}”: 1024-bit RSA key": "DKIM « {selector} » : clé RSA 1024 bits",
    "A 1024-bit key is now considered insufficient in the medium term; 2048 bits is the "
    "current recommendation.": (
        "Une clé de 1024 bits est jugée aujourd'hui insuffisante à moyen terme ; 2048 bits est "
        "la recommandation actuelle."
    ),
    "Regenerate the key as 2048-bit RSA at your provider and publish the new TXT record.": (
        "Régénérer la clé en RSA 2048 bits chez votre fournisseur et publier le nouvel "
        "enregistrement TXT."
    ),
    "DKIM “{selector}”: {bits}-bit RSA key": "DKIM « {selector} » : clé RSA {bits} bits",
    "The published DKIM key has a satisfactory size.": (
        "La clé DKIM publiée a une taille satisfaisante."
    ),
    # ------------------------------------------------------------------ email.dmarc
    "DMARC": "DMARC",
    "DMARC missing": "DMARC absent",
    "No DMARC policy is published. Receiving servers do not know what to do with email "
    "spoofing your domain (fake invoices, phishing…), and you receive no report.": (
        "Aucune politique DMARC n'est publiée. Les serveurs destinataires ne savent pas quoi "
        "faire des emails qui usurpent votre domaine (faux emails de facture, hameçonnage…), et "
        "vous ne recevez aucun rapport."
    ),
    "; start with “p=none” to watch the reports, then move to “p=quarantine” and finally "
    "“p=reject”": (
        "; commencer en « p=none » pour observer les rapports, puis passer à « p=quarantine » "
        "et enfin « p=reject »"
    ),
    "DMARC: several records": "DMARC : plusieurs enregistrements",
    "Several DMARC records are published: the standard then requires ignoring all of them. "
    "Result: no DMARC protection.": (
        "Plusieurs enregistrements DMARC sont publiés : la norme impose alors de les ignorer "
        "tous. Résultat : aucune protection DMARC."
    ),
    "Keep only ONE TXT record on _dmarc.{domain} (merge the “rua=” values if needed).": (
        "Ne conserver qu'UN seul enregistrement TXT sur _dmarc.{domain} (fusionner les « rua= » "
        "si besoin)."
    ),
    "DMARC: no report address (rua)": "DMARC : pas d'adresse de rapports (rua)",
    "Without a “rua” address, you do not receive the reports showing who sends email on your "
    "behalf: hard to spot spoofing or to move safely to “reject”.": (
        "Sans adresse « rua », vous ne recevez pas les rapports qui montrent qui envoie des "
        "emails en votre nom : difficile de repérer une usurpation ou de passer sereinement en "
        "« reject »."
    ),
    "Add to the record:": "Ajouter à l'enregistrement :",
    "DMARC: invalid “rua” address": "DMARC : adresse « rua » invalide",
    "The report address does not start with “mailto:”: it will be ignored.": (
        "L'adresse de rapports ne commence pas par « mailto: » : elle sera ignorée."
    ),
    "DMARC: invalid “pct” value": "DMARC : valeur « pct » invalide",
    "The enforcement percentage is not an integer between 0 and 100.": (
        "Le pourcentage d'application n'est pas un entier entre 0 et 100."
    ),
    "DMARC: policy applied to only {pct}%": "DMARC : politique appliquée à {pct} % seulement",
    "With pct={pct}, only {pct}% of fraudulent email is subject to the policy; the rest gets "
    "through. Meant for a gradual rollout, not as a final state.": (
        "Avec pct={pct}, seuls {pct} % des emails frauduleux subissent la politique ; les autres "
        "passent. Prévu pour une montée en charge progressive, pas comme état final."
    ),
    "Once reports are checked: remove “pct=” (or set pct=100).": (
        "Une fois les rapports vérifiés : retirer « pct= » (ou mettre pct=100)."
    ),
    "{title} (inherited from _dmarc.{domain})": "{title} (hérité de _dmarc.{domain})",
    "DMARC: “reject” policy": "DMARC : politique « reject »",
    "Email spoofing the domain is refused by compatible receivers: this is the maximum "
    "protection level.": (
        "Les emails qui usurpent le domaine sont refusés par les destinataires compatibles : "
        "c'est le niveau de protection maximal."
    ),
    "DMARC: “quarantine” policy": "DMARC : politique « quarantine »",
    "Email spoofing the domain is sent to spam. Good protection level; “reject” is the final "
    "step.": (
        "Les emails qui usurpent le domaine sont envoyés en spam. Bon niveau de protection ; "
        "« reject » est l'étape finale."
    ),
    "DMARC: “none” policy (monitoring only)": "DMARC : politique « none » (surveillance seule)",
    "DMARC is in observation mode: spoofed email is flagged in reports but still delivered. "
    "It is a starting step, not a protection.": (
        "DMARC est en mode observation : les emails usurpés sont signalés dans les rapports mais "
        "restent livrés. C'est une étape de départ, pas une protection."
    ),
    "After analyzing the reports and adjusting SPF/DKIM:": (
        "Après analyse des rapports et ajustement de SPF/DKIM :"
    ),
    "DMARC: “p” policy missing or invalid": "DMARC : politique « p » absente ou invalide",
    "The DMARC record exists but its policy (p=none|quarantine|reject) is missing or unknown: "
    "it has no effect.": (
        "L'enregistrement DMARC existe mais sa politique (p=none|quarantine|reject) est "
        "manquante ou inconnue : il est inopérant."
    ),
    # ------------------------------------------------------------------ email.dnssec
    "DNSSEC": "DNSSEC",
    "DNSSEC enabled": "DNSSEC activé",
    "The domain's DNS answers are signed: they are hard to forge in order to redirect your "
    "visitors or your mail.": (
        "Les réponses DNS du domaine sont signées : il est difficile de les falsifier pour "
        "rediriger vos visiteurs ou votre courrier."
    ),
    "DNSSEC not enabled": "DNSSEC non activé",
    "The domain's DNS answers are not signed. This is not a flaw in itself, but DNSSEC "
    "protects against forged records (website, email, SPF/DKIM/DMARC).": (
        "Les réponses DNS du domaine ne sont pas signées. Ce n'est pas une faille en soi, mais "
        "DNSSEC protège contre la falsification des enregistrements (site, emails, "
        "SPF/DKIM/DMARC)."
    ),
    "Enable DNSSEC at your DNS host, then publish the provided DS record at your registrar.": (
        "Activer DNSSEC chez votre hébergeur DNS, puis publier l'enregistrement DS fourni auprès "
        "de votre registrar."
    ),
    # ------------------------------------------------------------------ email.tls_rpt
    "TLS-RPT": "TLS-RPT",
    "TLS-RPT not configured": "TLS-RPT non configuré",
    "TLS-RPT sends daily reports when a sender fails to encrypt an email to you. Useful to "
    "roll out MTA-STS safely.": (
        "TLS-RPT envoie des rapports quotidiens quand un expéditeur n'arrive pas à chiffrer un "
        "email vers vous. Utile pour déployer MTA-STS sans risque."
    ),
    "several records": "plusieurs enregistrements",
    "“rua” address missing or invalid": "adresse « rua » manquante ou invalide",
    "TLS-RPT: invalid record": "TLS-RPT : enregistrement invalide",
    "The TLS-RPT record is unusable ({reason}).": "L'enregistrement TLS-RPT est inutilisable ({reason}).",
    "TLS-RPT configured": "TLS-RPT configuré",
    "You receive reports about encryption failures of incoming email.": (
        "Vous recevez des rapports sur les échecs de chiffrement des emails entrants."
    ),
    # ------------------------------------------------------------------ email.bimi
    "BIMI": "BIMI",
    "BIMI not configured": "BIMI non configuré",
    "BIMI shows your brand logo in the inbox of compatible recipients. Purely optional: it "
    "requires a strict DMARC (quarantine/reject) and, for Gmail/Apple, a mark certificate.": (
        "BIMI affiche le logo de votre marque dans la boîte de réception des destinataires "
        "compatibles. Purement optionnel : il demande un DMARC strict (quarantine/reject) et, "
        "pour Gmail/Apple, un certificat de marque."
    ),
    "BIMI: logo (l=) missing or not HTTPS": "BIMI : logo (l=) manquant ou non HTTPS",
    "The BIMI record must point to an SVG logo served over HTTPS.": (
        "L'enregistrement BIMI doit pointer vers un logo SVG servi en HTTPS."
    ),
    "BIMI configured": "BIMI configuré",
    "A brand logo is declared for display in mail clients.": (
        "Un logo de marque est déclaré pour l'affichage dans les messageries."
    ),
    "Without a certificate (a=), some clients will not show it.": (
        "Sans certificat (a=), certains clients ne l'afficheront pas."
    ),
}
