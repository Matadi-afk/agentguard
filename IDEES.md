# Idées en attente

Le parking à idées. Une idée qui ne sert pas la phrase du projet atterrit ici,
**pas dans le code**. On relit ce fichier au jour 30 (4 novembre 2026), pas avant.

> agentguard aide les développeurs qui branchent des agents IA à leurs outils
> à ne pas fuiter leurs secrets ni ouvrir leur machine.

## Depuis les prototypes Bundi
- Analyse AST du code des serveurs MCP (subprocess, eval, réseau caché)
- Base de menaces des paquets MCP alimentée par NVD/OTX (offre Pro)
- Réputation VirusTotal des paquets et URL MCP
- `agentguard fix` : propose une config corrigée, n'exécute jamais seul
- Rapport HTML (ex-dashboard Streamlit) pour la version Pro
- Au placard : forensique d'images, EDR + quarantaine

## Retours du premier test réel (6 octobre 2026, projets Bundi)
- **AG002 – secret générique** : repérer `NOM_API_KEY=valeur`, `*_TOKEN=`, `*_SECRET=` quand la
  valeur est littérale, même sans préfixe connu. Cas réel : clés NVD (format UUID), OTX et
  VirusTotal (64 caractères hexadécimaux) non détectées dans `bundi-ai/.env`.
- **Préfixes à ajouter** : Groq (`gsk_`), puis vérifier les formats d'autres fournisseurs IA.
- **`.env` protégé ou non** : alerte critique si le `.env` n'est PAS couvert par `.gitignore`,
  simple information s'il l'est (évite le faux positif vu sur `bundi_proto/.env`).
- **Serveur de modèles exposé** : signaler `OLLAMA_HOST=0.0.0.0` (API Ollama ouverte au réseau,
  sans authentification). Même idée pour d'autres serveurs d'IA locaux.
- **Ignorer une alerte sur une ligne** : commentaire du type `agentguard: ignore AG106`.
- **Socket Docker légitime** : certains serveurs MCP gèrent des conteneurs et en ont besoin ;
  prévoir une façon documentée d'accepter ce risque en connaissance de cause.
- **VS Code** : lire aussi la clé `"mcp"` de `settings.json`, pas seulement les fichiers `mcp.json`.

## Nouvelles idées
-
