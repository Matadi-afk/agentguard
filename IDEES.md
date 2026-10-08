# Idées en attente

Le parking à idées. Une idée qui ne sert pas la phrase du projet atterrit ici,
**pas dans le code**. On relit ce fichier au jour 30 (4 novembre 2026), pas avant.

> agentguard aide les développeurs qui branchent des agents IA à leurs outils
> à ne pas fuiter leurs secrets ni ouvrir leur machine.

## Depuis des prototypes antérieurs
- Analyse AST du code des serveurs MCP (subprocess, eval, réseau caché)
- Base de menaces des paquets MCP alimentée par NVD/OTX (offre Pro)
- Réputation VirusTotal des paquets et URL MCP
- `agentguard fix` : propose une config corrigée, n'exécute jamais seul
- Rapport HTML (ex-dashboard Streamlit) pour la version Pro
- Au placard : forensique d'images, EDR + quarantaine

## Retours du premier test réel (6 octobre 2026)
- **AG002 – secret générique** : repérer `NOM_API_KEY=valeur`, `*_TOKEN=`, `*_SECRET=` quand la
  valeur est littérale, même sans préfixe connu (clés au format UUID ou hexadécimal, qui n'ont
  pas de préfixe reconnaissable).
- **Préfixes à ajouter** : Groq (`gsk_`), puis vérifier les formats d'autres fournisseurs IA.
- **`.env` protégé ou non** : alerte critique si le `.env` n'est PAS couvert par `.gitignore`,
  simple information s'il l'est (évite un faux positif observé).
- **Serveur de modèles exposé** : signaler `OLLAMA_HOST=0.0.0.0` (API Ollama ouverte au réseau,
  sans authentification). Même idée pour d'autres serveurs d'IA locaux.
- **Ignorer une alerte** : le JSON n'accepte pas de commentaires, donc pas de `# ignore` dans
  `mcp.json`. Piste retenue : un fichier `.agentguard-ignore` (ID de règle + chemin + raison
  obligatoire), constats ignorés toujours comptés, option `--no-ignore`, `suppressions` en SARIF.
- **Socket Docker légitime** : certains serveurs MCP gèrent des conteneurs et en ont besoin ;
  prévoir une façon documentée d'accepter ce risque en connaissance de cause.

## Retours de la revue de sécurité (7 octobre 2026)
- **Règle « Trojan Source »** : signaler les caractères invisibles ou bidirectionnels dans les
  fichiers de configuration et le code analysés (déjà vérifié pour notre propre code).
- **Identifiants dans les URL** : détecter `https://user:motdepasse@…` partout, pas seulement
  dans les paquets MCP.

## Angles morts relevés par la revue indépendante (7 octobre 2026)
- **AG101** : `bash -lc`, `wsl.exe bash -c`, `/usr/bin/env sh -c`, `pwsh -e` non détectés.
- **Lanceurs Windows** : `npx.cmd` (seul `.exe` est retiré du nom).
- **AG102** : `@^1.0.0`, `@1` et `@beta` comptés comme figés à tort.
- **AG107** : `git@github.com:…` et la syntaxe PEP 508 `srv @ git+https://…` non détectés.
- **AG104 / AG106** : `/Users/nom`, `C:\Users\nom`, `c:\` en minuscule, montage `~/.ssh`.
- **SARIF** : chemins relatifs au dossier scanné, pas à la racine du dépôt (ajouter `uriBaseId`).
- **AG103** : `DATABASE_URL` contenant un mot de passe.
- **AG103 (faux positifs)** : ne pas signaler les modèles `<YOUR_KEY>` ni les références
  `${VAR:-défaut}`, `%VAR%`, `${{ secrets.NOM }}` (mais vérifier une valeur par défaut écrite
  en clair).
- **Commandes enveloppées** : `cmd /c npx …`, `wsl bash -c …`, `env sh -c …` : analyser aussi
  la commande intérieure (aujourd'hui, AG102 et AG107 ne la voient pas).

## Recherche des Éclaireurs (8 octobre 2026)
- **TOML et YAML** (décision du 8 octobre : plus tard) : Codex CLI (`config.toml`,
  `[mcp_servers.nom]`, lisible avec `tomllib` à partir de Python 3.11) ; Continue
  (`config.yaml`, `.continue/mcpServers/*.yaml`, qui demanderait une dépendance).
- **Commandes cachées hors de `command`** : Claude Code `headersHelper` (commande qui produit
  les en-têtes HTTP) ; Gemini CLI `mcp.serverCommand`.
- **Contenu de fichier injecté** : Windsurf/Devin `${file:/chemin}` insère un fichier dans une
  URL ou un en-tête : alerte s'il vise des identifiants (`~/.ssh`, `.env`…).
- **Extensions de bureau** : manifeste `manifest.json` des paquets `.mcpb` / `.dxt`
  (`server.mcp_config`).
- **Agents** : serveurs déclarés dans l'en-tête YAML des agents Claude Code
  (`.claude/agents/*.md`) et Kiro (`.kiro/agents/*.md`).

## Nouvelles idées
-
