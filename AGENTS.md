# AGENTS.md : guide du projet pour les assistants IA

Ce fichier résume le projet pour qu'un assistant IA (Claude, Copilot, Cursor…) puisse travailler **sans relire tout le code**. Il doit rester court et à jour : quand la structure, une commande ou une règle change, on met ce fichier à jour dans le même commit.

> ⚠️ Ce fichier est public. Il ne doit **jamais** contenir de secret, de chemin personnel ni d'information privée.

## Le projet en une phrase

**configwarden** aide les développeurs qui branchent des agents IA à leurs outils à ne pas fuiter leurs secrets ni ouvrir leur machine.

Anciennement **agentguard** : renommé le 8 octobre 2026, car ce nom était trop proche de projets existants (PyPI le refusait, et un autre outil MCP installe déjà une commande `agentguard`). Les règles gardent leurs numéros avec le préfixe `CW` (`AG103` → `CW103`).

Il s'agit d'un scanner en ligne de commande, open source (Apache‑2.0), écrit en Python ≥ 3.10, **sans aucune dépendance à l'exécution**. Il produit des rapports en texte, JSON ou SARIF.

Toute idée qui ne sert pas cette phrase va dans `IDEES.md`, pas dans le code.

## Carte du code

```
src/configwarden/
  cli.py            Commandes `scan` et `rules`, codes de sortie 0/1/2 ; --output refuse d'écrire à travers un lien symbolique
  scanner.py        Parcours des fichiers (sans suivre les symlinks ; fichiers ordinaires seulement ; ignore binaires et > 1 Mo ; lit l'UTF-16/32 avec BOM) + appel des règles
  models.py         Severity (LOW < MEDIUM < HIGH < CRITICAL), Rule, Finding (chemin et message assainis à la création)
  commands.py       analyse() : retire les enveloppes (cmd /c, wsl, env, sudo, bash -c…) et relève les risques CW101
  jsonc.py          loads() : JSON strict, sinon JSON avec commentaires et virgules finales (temps linéaire, positions conservées)
  redact.py         redact() masque un secret ; redact_url() masque identifiants et paramètres d'URL ; url_origin() ne garde que « schéma://hôte/… » ; sanitize() neutralise les caractères de contrôle et invisibles
  config.py         Secret + get_secret() : lecture sécurisée des variables d'environnement (étape 8)
  rules/
    __init__.py     ALL_RULES = liste de toutes les règles
    secrets.py      CW001 : secrets en clair (regex par fournisseur)
    mcp.py          CW100-CW108 : configurations MCP dangereuses ; lit tout fichier .json/.jsonc (voir « Formats reconnus »)
  reporters/        text.py, json_reporter.py, sarif.py (+ RENDERERS dans __init__)
tests/              pytest ; conftest.py fournit fake_secret() et write_mcp ; test_hardening.py rejoue les attaques connues ; test_real_configs.py couvre le format de chaque outil IA
examples/           vulnerable-mcp/ (doit déclencher CW101-CW108) et safe-mcp/ (doit rester propre)
docs/GUIDE-FR.md    Guide d'installation pas à pas pour débutant (Windows/macOS)
```

## Règles existantes

| ID | Gravité | Fichier | Détecte |
|----|---------|---------|---------|
| CW001 | critical | rules/secrets.py | Clé API ou token en clair |
| CW100 | medium | rules/mcp.py | Config MCP illisible (certains outils lancent quand même une partie d'un fichier abîmé) |
| CW101 | high | rules/mcp.py | Shell qui reçoit un script (`bash -c`, `pwsh -Command`), `cmd /c` avec une ligne de commande ou des caractères spéciaux, code en ligne (`node -e`, `python -c`) |
| CW102 | medium | rules/mcp.py | Paquet `npx`/`uvx` sans version **exacte** (`^1.0`, `@beta`, `>=1` ne comptent pas) |
| CW103 | high | rules/mcp.py | Secret littéral dans `env` ou `headers`, y compris mot de passe dans une URL et valeur par défaut de `${VAR:-…}` (références et modèles `<YOUR_KEY>` ignorés) |
| CW104 | high | rules/mcp.py | Serveur filesystem ouvert sur `/`, un lecteur entier ou un dossier personnel complet |
| CW105 | high | rules/mcp.py | Serveur distant en `http://` |
| CW106 | high | rules/mcp.py | Conteneur Docker/Podman qui casse l'isolation (`--privileged`, `=host`, montage de `/`, du dossier personnel, de `.ssh`/`.aws`… ou du socket Docker) |
| CW107 | high | rules/mcp.py | Paquet installé depuis git, une URL, un raccourci GitHub `auteur/projet` ou `nom @ url` (remplace CW102 pour ce paquet) |
| CW108 | medium | rules/mcp.py | Outils approuvés sans confirmation (`alwaysAllow`, `autoApprove`, `trust: true`) |

Prochain ID libre : **CW002** (secrets) ou **CW110** (MCP). **CW109** est réservé à la règle « l'outil IA approuve tout sans demander » (décidée le 8 octobre 2026).

## Formats reconnus

configwarden lit **tout fichier `.json` ou `.jsonc`** (commentaires et virgules finales acceptés, voir `jsonc.py`) et cherche les serveurs MCP à ces emplacements. La recherche se fait après la lecture du fichier : un nom de clé écrit avec des échappements ne cache rien.

| Emplacement | Outils |
|---|---|
| `mcpServers` | Claude Desktop, Claude Code (`.mcp.json`), Cursor, Gemini CLI, Cline, Roo Code, Windsurf/Devin, Kiro, Amazon Q, Copilot CLI |
| `servers` (fichiers « nommés MCP » seulement) | VS Code (`.vscode/mcp.json`) |
| `mcp.servers` | VS Code, ancien `settings.json` |
| `customizations.vscode.mcp.servers` | `devcontainer.json` |
| `context_servers` | Zed (`command` texte, ou objet `{path, args, env}` dans l'ancien format) |
| `projects.<chemin>.mcpServers` | Claude Code (`~/.claude.json`, serveurs par projet) |

- Fichiers « nommés MCP » (illisibles → CW100) : `mcp.json`, `.mcp.json`, `*.mcp.json`, `mcp_config.json`, `claude_desktop_config.json`, `cline_mcp_settings.json`, `mcp_settings.json`, `mcp-config.json`. Les autres fichiers JSON illisibles restent silencieux.
- Adresses distantes : `url`, `serverUrl` (Windsurf), `httpUrl` (Gemini CLI).
- **Jamais de silence sur une configuration non auditable** (CW100) : fichier MCP ou JSON d'un dossier d'outil IA (`.vscode/`, `.cursor/`, `.gemini/`, `.claude/`…) trop gros, d'apparence binaire ou lien symbolique ; fichier JSON abîmé qui annonce des serveurs. Un outil tolérant pourrait lancer ce que configwarden n'a pas lu.
- Pas encore pris en charge (voir `IDEES.md`) : YAML (Continue), TOML (Codex CLI).
- Source : documentation officielle de chaque outil, relevée le 8 octobre 2026. À revérifier quand un outil change de format.

## Commandes

Elles se lancent depuis la racine du projet, avec l'environnement `.venv` activé (Windows PowerShell : `.venv\Scripts\Activate.ps1`).

```bash
pip install -e ".[dev]"                     # installation (une fois)
pytest                                      # tests
ruff check . ; ruff format .                # qualité + sécurité (règles Bandit "S")
pre-commit run --all-files                  # tous les contrôles, dont gitleaks
configwarden scan examples/vulnerable-mcp     # démo : 10 constats attendus
configwarden scan . --exclude "examples/*"    # auto-scan : 0 constat attendu
```

## Ajouter une règle (procédure)

1. Déclarer un `Rule(id=..., title=..., severity=..., remediation=...)` dans le bon fichier de `rules/`, puis l'ajouter à la liste `RULES` de ce fichier.
2. Écrire la détection. Elle doit produire des `Finding` dont le `message` n'expose **jamais** une valeur sensible : passer par `redact()` (valeur) ou `url_origin()` (URL).
3. Ajouter des tests : au moins un cas détecté et un cas propre (faux positif évité).
4. Si la règle concerne MCP, l'ajouter dans `examples/vulnerable-mcp/mcp.json` et vérifier que `examples/safe-mcp` reste propre.
5. Mettre à jour le tableau des règles ici **et** dans `README.md`.
6. `pytest` et `pre-commit run --all-files` doivent passer.

## Règles de sécurité (non négociables)

- **Aucun secret dans le dépôt**, même faux. Dans les tests, les faux secrets sont **assemblés à l'exécution** avec `fake_secret("ghp_", 36)` : jamais de chaîne littérale au format d'une vraie clé. Les paramètres de test utilisent `ids=` pour qu'aucune valeur n'apparaisse dans les noms de tests.
- **Un rapport n'affiche jamais un secret en entier** (texte, JSON comme SARIF).
- **Zéro dépendance à l'exécution** : `dependencies = []` dans `pyproject.toml`. Toute nouvelle dépendance doit être justifiée et validée par le mainteneur.
- Les secrets de l'application se lisent via `config.get_secret()` et restent enveloppés dans `Secret` jusqu'à `.reveal()`.
- Pas d'`eval`, d'`exec`, de `pickle`, ni de `subprocess` avec `shell=True`.
- Le scanner lit, il n'exécute jamais rien de ce qu'il analyse.
- Ne pas désactiver un contrôle (`--no-verify`, `# noqa` non justifié) pour faire passer un commit.

## Checklist sécurité (obligatoire pour TOUTE modification)

Fil rouge du projet : configwarden est un outil de sécurité, il doit être lui-même irréprochable. Avant de proposer un changement, vérifier chaque point :

1. **Entrées non fiables** : tout ce qui vient d'un fichier analysé (JSON, texte, noms de fichiers) peut être piégé. Vérifier les types (`isinstance`), ne jamais supposer une structure, et ne jamais laisser une exception arrêter le scan (penser aux fichiers énormes, très imbriqués ou malformés, aux URL invalides, aux fichiers spéciaux).
2. **Temps de calcul** : jamais de traitement quadratique sur une entrée (une boucle qui relit tout le fichier pour chaque élément, une regex qui peut revenir en arrière). Tester avec une entrée de ~1 Mo construite pour être lente.
3. **Sorties assainies** : les textes affichés passent par `Finding`, qui applique `sanitize()`. Ne jamais afficher une donnée lue sans passer par là.
4. **Secrets masqués** : valeur sensible → `redact()` ; URL → `url_origin()` dans un message (un jeton peut se cacher dans les identifiants, le chemin ou les paramètres). Ne jamais recopier un message d'erreur Python qui contient l'entrée.
5. **Écritures sûres** : ne jamais écrire à travers un lien symbolique (le dossier analysé n'est pas fiable).
6. **Aucune nouvelle dépendance** à l'exécution, et pas d'action CI non figée par empreinte SHA.
7. **Un test « malveillant »** pour chaque nouvelle règle ou entrée : il doit échouer sans la protection et passer avec (« test du test »).
8. **Pas de caractère invisible** dans le code : un caractère spécial s'écrit avec `chr(0x…)`. Le test `test_no_invisible_or_bidi_characters_in_source` le vérifie.
9. **Exposition** : rien de personnel ni de privé dans les fichiers publics (vrai nom, chemins locaux, noms de projets privés, inventaire de clés).
10. **Contre-vérification** : pour un changement de sécurité, faire relire le correctif par une revue indépendante qui tente de le contourner. Un correctif peut introduire une nouvelle faille (vécu en 0.2.2).

## Conventions

- Code, messages du CLI et README **en anglais** (public international). Commentaires, docstrings et documentation `docs/` **en français**.
- Lignes de 100 caractères maximum ; format et imports gérés par ruff.
- Chemins des constats relatifs et avec des `/`, quel que soit le système d'exploitation.

## Fichiers à ne pas modifier sans accord explicite du mainteneur

`.github/workflows/`, `.pre-commit-config.yaml`, `.gitignore`, `LICENSE`, `pyproject.toml` (section `dependencies`).

## État du projet

- Version 0.2.2 publiée (10 règles, deux séries de correctifs de sécurité). v0.3.0 en cours : vrais fichiers de configuration (jour 1), commandes enveloppées et angles morts CW101 à CW107 (jour 2). 357 tests. Notes de version dans `CHANGELOG.md` : à compléter à chaque nouvelle version.
- Cap fixé jusqu'au 4 novembre 2026 : publier sur GitHub, ajouter 3 règles, faire un premier post. Voir `IDEES.md` pour ce qui est volontairement mis de côté.
