# AGENTS.md : guide du projet pour les assistants IA

Ce fichier résume le projet pour qu'un assistant IA (Claude, Copilot, Cursor…) puisse travailler **sans relire tout le code**. Il doit rester court et à jour : quand la structure, une commande ou une règle change, on met ce fichier à jour dans le même commit.

> ⚠️ Ce fichier est public. Il ne doit **jamais** contenir de secret, de chemin personnel ni d'information privée.

## Le projet en une phrase

**agentguard** aide les développeurs qui branchent des agents IA à leurs outils à ne pas fuiter leurs secrets ni ouvrir leur machine.

Il s'agit d'un scanner en ligne de commande, open source (Apache‑2.0), écrit en Python ≥ 3.10, **sans aucune dépendance à l'exécution**. Il produit des rapports en texte, JSON ou SARIF.

Toute idée qui ne sert pas cette phrase va dans `IDEES.md`, pas dans le code.

## Carte du code

```
src/agentguard/
  cli.py            Commandes `scan` et `rules`, codes de sortie 0/1/2
  scanner.py        Parcours des fichiers (sans suivre les symlinks, ignore binaires et fichiers > 1 Mo) + appel des règles
  models.py         Severity (LOW < MEDIUM < HIGH < CRITICAL), Rule, Finding
  redact.py         redact() : masque un secret (« ghp_****…(40 chars) »)
  config.py         Secret + get_secret() : lecture sécurisée des variables d'environnement (étape 8)
  rules/
    __init__.py     ALL_RULES = liste de toutes les règles
    secrets.py      AG001 : secrets en clair (regex par fournisseur)
    mcp.py          AG100-AG105 : configurations MCP dangereuses
  reporters/        text.py, json_reporter.py, sarif.py (+ RENDERERS dans __init__)
tests/              pytest ; conftest.py fournit fake_secret() et la fixture write_mcp
examples/           vulnerable-mcp/ (doit déclencher AG101-AG105) et safe-mcp/ (doit rester propre)
docs/GUIDE-FR.md    Guide d'installation pas à pas pour débutant (Windows/macOS)
```

## Règles existantes

| ID | Gravité | Fichier | Détecte |
|----|---------|---------|---------|
| AG001 | critical | rules/secrets.py | Clé API ou token en clair |
| AG100 | low | rules/mcp.py | Config MCP en JSON invalide |
| AG101 | high | rules/mcp.py | Serveur lancé via un shell (`bash -c`, `cmd /c`…) |
| AG102 | medium | rules/mcp.py | Paquet `npx`/`uvx` sans version figée |
| AG103 | high | rules/mcp.py | Secret littéral dans `env` ou `headers` |
| AG104 | high | rules/mcp.py | Serveur filesystem ouvert sur `/`, `~`, `C:\` |
| AG105 | high | rules/mcp.py | Serveur distant en `http://` |

Prochain ID libre : **AG002** (secrets) ou **AG106** (MCP).

## Commandes

Elles se lancent depuis la racine du projet, avec l'environnement `.venv` activé (Windows PowerShell : `.venv\Scripts\Activate.ps1`).

```bash
pip install -e ".[dev]"                     # installation (une fois)
pytest                                      # tests
ruff check . && ruff format .               # qualité + sécurité (règles Bandit "S")
pre-commit run --all-files                  # tous les contrôles, dont gitleaks
agentguard scan examples/vulnerable-mcp     # démo : 6 constats attendus
agentguard scan . --exclude "examples/*"    # auto-scan : 0 constat attendu
```

## Ajouter une règle (procédure)

1. Déclarer un `Rule(id=..., title=..., severity=..., remediation=...)` dans le bon fichier de `rules/`, puis l'ajouter à la liste `RULES` de ce fichier.
2. Écrire la détection. Elle doit produire des `Finding` dont le `message` n'expose **jamais** une valeur sensible : passer par `redact()`.
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

## Conventions

- Code, messages du CLI et README **en anglais** (public international). Commentaires, docstrings et documentation `docs/` **en français**.
- Lignes de 100 caractères maximum ; format et imports gérés par ruff.
- Chemins des constats relatifs et avec des `/`, quel que soit le système d'exploitation.

## Fichiers à ne pas modifier sans accord explicite du mainteneur

`.github/workflows/`, `.pre-commit-config.yaml`, `.gitignore`, `LICENSE`, `pyproject.toml` (section `dependencies`).

## État du projet

- Version 0.1.0 (MVP). 67 tests.
- Cap fixé jusqu'au 4 novembre 2026 : publier sur GitHub, ajouter 3 règles, faire un premier post. Voir `IDEES.md` pour ce qui est volontairement mis de côté.
