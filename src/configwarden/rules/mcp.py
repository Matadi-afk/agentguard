"""Règles CW1xx : configurations de serveurs MCP dangereuses.

MCP (Model Context Protocol) permet à un agent IA (Claude, Cursor, VS Code…)
d'utiliser des outils externes. Une mauvaise config peut donner à l'IA, ou
à quelqu'un qui la manipule par injection de prompt, un accès bien trop large.

Emplacements des serveurs reconnus (documentation officielle, octobre 2026) :
  {"mcpServers": {...}}                       Claude Desktop, Claude Code, Cursor, Gemini CLI,
                                              Cline, Roo Code, Windsurf, Kiro, Amazon Q…
  {"servers": {...}}                          VS Code (.vscode/mcp.json), fichiers « mcp » seulement
  {"mcp": {"servers": {...}}}                 VS Code, ancien format de settings.json
  {"customizations": {"vscode": {"mcp":
      {"servers": {...}}}}}                   conteneur de développement (devcontainer.json)
  {"context_servers": {...}}                  Zed (settings.json)
  {"projects": {"/chemin": {"mcpServers"}}}   Claude Code (~/.claude.json, serveurs par projet)

Tout fichier .json ou .jsonc est lu, commentaires compris (voir jsonc.py) ; il n'est
analysé que s'il contient l'une de ces structures. La détection se fait APRÈS la
lecture : un nom de clé écrit avec des échappements (« mcp\\u0053ervers ») ne
permet pas de cacher un serveur.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from urllib.parse import urlparse

from configwarden import commands, jsonc
from configwarden.models import Finding, Rule, Severity
from configwarden.redact import redact, redact_url, url_origin

# --- Définition des règles -----------------------------------------------------

# Gravité moyenne (décision du 8 octobre 2026) : certains outils IA tolèrent les
# erreurs de syntaxe et lancent quand même les serveurs qu'ils ont pu lire. Un
# fichier abîmé exprès pourrait donc cacher un serveur à configwarden.
INVALID_CONFIG = Rule(
    id="CW100",
    title="Unreadable MCP configuration",
    severity=Severity.MEDIUM,
    remediation=(
        "Fix the JSON syntax so the configuration can be audited. Some AI clients still "
        "start the servers they can read from a broken file."
    ),
)
SHELL_EXECUTION = Rule(
    id="CW101",
    title="MCP server runs a shell script or inline code",
    severity=Severity.HIGH,
    remediation=(
        "Call the server program directly, with its arguments as separate items (on Windows, "
        "`cmd /c` followed by the program and its arguments is fine). A script given to "
        "`bash -c`, a command-line string or inline code (`node -e`) enables command "
        "injection and hides what really runs."
    ),
)
UNPINNED_PACKAGE = Rule(
    id="CW102",
    title="Unpinned MCP package version",
    severity=Severity.MEDIUM,
    remediation=(
        "Pin an exact version (e.g. `@scope/pkg@1.2.3` or `pkg==1.2.3`). Without it, "
        "a compromised new release would run automatically on your machine."
    ),
)
HARDCODED_ENV_SECRET = Rule(
    id="CW103",
    title="Secret hardcoded in MCP configuration",
    severity=Severity.HIGH,
    remediation=(
        "Reference an environment variable (e.g. `${GITHUB_TOKEN}` or "
        "`${env:GITHUB_TOKEN}`) instead of writing the value in the file."
    ),
)
BROAD_FILESYSTEM = Rule(
    id="CW104",
    title="Overly broad filesystem access",
    severity=Severity.HIGH,
    remediation=(
        "Grant access only to the project folder the agent needs, never the root "
        "or home directory (which contains SSH keys, browser data, .env files…)."
    ),
)
INSECURE_TRANSPORT = Rule(
    id="CW105",
    title="Remote MCP server over plain HTTP",
    severity=Severity.HIGH,
    remediation="Use https:// so tokens and data cannot be intercepted.",
)

DANGEROUS_CONTAINER = Rule(
    id="CW106",
    title="MCP server container escapes isolation",
    severity=Severity.HIGH,
    remediation=(
        "Remove --privileged, host namespaces and mounts of '/', the home directory or the "
        "Docker socket. Mount only the project folder the server needs, read-only if possible."
    ),
)
UNTRUSTED_PACKAGE_SOURCE = Rule(
    id="CW107",
    title="MCP package installed from an unverified source",
    severity=Severity.HIGH,
    remediation=(
        "Install the server from the official registry (npm / PyPI) with a pinned version. "
        "A git repository or URL can change at any time and bypasses registry checks."
    ),
)
AUTO_APPROVED_TOOLS = Rule(
    id="CW108",
    title="MCP tools run without user confirmation",
    severity=Severity.MEDIUM,
    remediation=(
        "Remove `alwaysAllow` / `autoApprove` / `trust: true`, or limit it to read-only tools. "
        "Confirmation is the last barrier against a prompt-injected agent."
    ),
)

# CW109 (décision du 8 octobre 2026) : un réglage de l'outil IA, et non d'un serveur,
# qui supprime toute confirmation. Dans un dépôt, il transforme l'ouverture d'un
# projet piégé en exécution automatique de ses serveurs et de ses outils.
CLIENT_AUTO_APPROVE = Rule(
    id="CW109",
    title="AI client approves actions without confirmation",
    severity=Severity.HIGH,
    remediation=(
        "Turn off the global auto-approve setting and approve servers and tools one by one. "
        "Never commit such a setting to a repository: anyone who opens the project would run "
        "its servers and tools without being asked."
    ),
)

RULES = [
    INVALID_CONFIG,
    SHELL_EXECUTION,
    UNPINNED_PACKAGE,
    HARDCODED_ENV_SECRET,
    BROAD_FILESYSTEM,
    INSECURE_TRANSPORT,
    DANGEROUS_CONTAINER,
    UNTRUSTED_PACKAGE_SOURCE,
    AUTO_APPROVED_TOOLS,
    CLIENT_AUTO_APPROVE,
]

# --- Constantes de détection ---------------------------------------------------

# Fichiers propres à MCP : s'ils sont illisibles, on le signale (CW100), et la clé
# « servers » (VS Code) n'y est reconnue que là. Les autres fichiers JSON sont lus
# aussi, mais restent silencieux s'ils sont illisibles ou sans serveur MCP.
MCP_CONFIG_NAMES = {
    "mcp.json",  # VS Code, Cursor, Roo Code, Kiro, Amazon Q
    ".mcp.json",  # Claude Code, VS Code
    "mcp_config.json",  # Windsurf / Devin Desktop
    "claude_desktop_config.json",  # Claude Desktop
    "cline_mcp_settings.json",  # Cline
    "mcp_settings.json",  # Roo Code (global)
    "mcp-config.json",  # GitHub Copilot CLI
}
_JSON_SUFFIXES = (".json", ".jsonc")
# Dossiers de configuration des outils IA : un fichier JSON qu'on n'y peut pas lire
# (trop gros, binaire, lien symbolique…) est signalé, car l'outil, lui, peut le lire.
_CLIENT_FOLDERS = {
    ".amazonq",
    ".claude",
    ".codeium",
    ".codex",
    ".continue",
    ".copilot",
    ".cursor",
    ".devcontainer",
    ".devin",
    ".gemini",
    ".kiro",
    ".roo",
    ".vscode",
    ".windsurf",
    ".zed",
}
# Clés qui annoncent des serveurs MCP. Cherchées dans le texte brut d'un fichier
# JSON abîmé, après décodage des échappements « \\uXXXX ».
_MCP_MARKERS = ('"mcpServers"', '"context_servers"', '"mcp"')
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
# Clés qui désignent l'adresse d'un serveur distant, selon l'outil.
_URL_KEYS = ("url", "serverUrl", "httpUrl")
_PACKAGE_RUNNERS = {"npx", "pnpx", "bunx", "uvx"}
# Options dont la valeur désigne le paquet lancé (« -p » est --package pour npx,
# mais --python pour uvx).
_NPM_PACKAGE_FLAGS = {"--package", "-p"}
_UV_PACKAGE_FLAGS = {"--from"}
# uvx : paquets installés EN PLUS du serveur (leur code s'exécute aussi).
_EXTRA_PACKAGE_FLAGS = {"--with", "--with-editable"}
# Options suivies d'une valeur, PAR LANCEUR : « -f » vaut --force (sans valeur)
# pour npx mais --find-links (avec valeur) pour uvx. Sans ces listes, la valeur
# d'une option (« --registry https://… ») serait prise pour le paquet, et une
# option sans valeur (« -f ») ferait sauter le vrai paquet. Une option inconnue
# est supposée SANS valeur (cas de « -y »).
_NPM_OPTIONS_WITH_VALUE = {
    "--package",
    "-p",
    "--call",
    "-c",
    "--registry",
    "--cache",
    "--userconfig",
    "--prefix",
    "--loglevel",
    "--workspace",
    "-w",
}
_UV_OPTIONS_WITH_VALUE = {
    "--from",
    "--with",
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--index",
    "--index-url",
    "--extra-index-url",
    "--default-index",
    "--find-links",
    "-f",
    "--directory",
    "--project",
    "--cache-dir",
    "--config-file",
    "--constraints",
    "--overrides",
    "--exclude-newer",
    "--index-strategy",
    "--keyring-provider",
    "--python-preference",
}
# « PAT » (Personal Access Token) seulement comme mot entier : sinon PATH, PATTERN…
# seraient pris pour des secrets. « PASS » couvre PASSWORD, PASSWD, DB_PASS…
_SENSITIVE_KEY = re.compile(
    r"KEY|TOKEN|SECRET|PASS|(?<![A-Z])PAT(?![A-Z])|AUTH|CREDENTIAL", re.IGNORECASE
)
# CW103 : références à une variable (pas un secret) selon les outils :
# $VAR, ${VAR}, ${env:VAR}, ${input:id}, %VAR% (Windows), $env:VAR (PowerShell),
# ${{ secrets.NOM }} (Continue).
_ENV_REFERENCE = re.compile(
    r"\$\{?[A-Za-z_][A-Za-z0-9_:.]*\}?"
    r"|\$\{(?:env|input):.+\}"
    r"|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|\$env:[A-Za-z_][A-Za-z0-9_]*"
    r"|\$\{\{\s*[A-Za-z0-9_.]+\s*\}\}"
)
# ${VAR:-défaut} : la valeur par défaut, elle, peut être un vrai secret écrit en clair.
_DEFAULTED_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=](.*)\}", re.DOTALL)
# Modèles à remplir des documentations : <YOUR_KEY>, your-api-key-here, xxxx…
_PLACEHOLDER = re.compile(
    r"<[^<>]*>|\[[^\[\]]*\]|x{3,}|\*{3,}|\.{3,}|changeme|change-me|replace[-_ ]?me"
    r"|placeholder|todo|tbd|your[-_ ][a-z0-9_ -]+",
    re.IGNORECASE,
)
# Mot de passe dans une URL (postgres://user:motdepasse@hôte). Quantités bornées et
# début de mot obligatoire : temps linéaire même sur un texte piégé.
_URL_PASSWORD = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://[^/@\s:]{0,256}:([^@\s/]{1,512})@"
)
# CW104 / CW106 : dossiers trop larges (racine, lecteur, dossier personnel entier).
_BROAD_PATH = re.compile(
    r"/|/root|[a-z]:|(?:/home|/users|[a-z]:/users)(?:/[^/]+)?"
    r"|~|\$home|\$\{home\}|\$\{userhome\}|%userprofile%|%homepath%"
    r"|\$\{env:(?:userprofile|home)\}|\$env:(?:userprofile|home)",
    re.IGNORECASE,
)
# Dossiers d'identifiants, où qu'ils soient : .ssh, .aws, .gnupg, .kube, .docker…
_CREDENTIAL_FOLDER = re.compile(
    r"(?:^|/)\.(?:ssh|aws|gnupg|kube|docker|azure|config/gcloud)(?:/|$)", re.IGNORECASE
)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104 (liste de comparaison)

# CW106 : moteurs de conteneurs et options qui cassent l'isolation.
_CONTAINER_ENGINES = {"docker", "podman", "nerdctl"}
_HOST_NAMESPACE_FLAGS = {"--network", "--net", "--pid", "--ipc", "--uts", "--userns"}
_MOUNT_FLAGS = {"-v", "--volume"}
_DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN"}
_SENSITIVE_MOUNT_SOURCES = {"/etc", "/root", "/var/run", "/run"}

# CW107 : préfixes qui désignent un paquet hors registre officiel.
_UNTRUSTED_SOURCE_PREFIXES = (
    "git+",
    "git://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "http://",
    "https://",
    "ssh://",
    "hg+",
    "svn+",
    "bzr+",
)
# npm : « auteur/projet » (sans @ devant) désigne un dépôt GitHub, pas le registre.
_GITHUB_SHORTHAND = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(?:#\S*)?")
# Adresse git au format « scp » : git@github.com:auteur/projet.git
_SCP_GIT = re.compile(r"[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):\S+")
# Python (PEP 508) : « nom @ url » installe depuis cette adresse.
_PEP508_URL = re.compile(r"\s*[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*@\s*(\S+)\s*")
# Version exacte : npm (semver x.y.z) et Python (== ou @ suivi d'un numéro).
_NPM_EXACT_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_UV_EXACT_VERSION = re.compile(
    r"\s*[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*(?:===?|@)\s*v?\d[0-9A-Za-z.+!-]*\s*"
)

# CW108 : clés qui autorisent des outils sans confirmation, selon le client IA.
_AUTO_APPROVE_KEYS = ("alwaysAllow", "autoApprove")


def _normalize_path(arg: str) -> str:
    """'C:\\' -> 'C:' ; '~/' -> '~' ; '/' reste '/'."""
    return arg.strip().rstrip("/\\") or "/"


def is_mcp_config(path: PurePosixPath) -> bool:
    """Le fichier porte-t-il un nom propre aux configurations MCP ?"""
    name = path.name.lower()
    return name in MCP_CONFIG_NAMES or name.endswith((".mcp.json", ".mcp.jsonc"))


def is_json_file(path: PurePosixPath) -> bool:
    """Fichier JSON quelconque, à lire au cas où il contiendrait des serveurs MCP."""
    return path.name.lower().endswith(_JSON_SUFFIXES)


def is_client_config_path(path: PurePosixPath) -> bool:
    """Chemin d'une configuration d'outil IA (fichier MCP, ou JSON d'un dossier connu)."""
    name = path.name.lower()
    if is_mcp_config(path) or name == ".claude.json":
        return True
    in_client_folder = any(part.lower() in _CLIENT_FOLDERS for part in path.parts)
    return in_client_folder and (is_json_file(path) or name in _CLIENT_FOLDERS)


def unreadable_config_finding(path: str) -> Finding:
    """Fichier de configuration que configwarden n'a pas pu lire du tout."""
    return Finding(
        rule=INVALID_CONFIG,
        path=path,
        line=1,
        message=(
            "This AI client configuration could not be read (too large, binary or "
            "unreadable), so it cannot be audited."
        ),
    )


def symlinked_config_finding(path: str) -> Finding:
    """Configuration (ou dossier de configuration) qui est un lien symbolique."""
    return Finding(
        rule=INVALID_CONFIG,
        path=path,
        line=1,
        message=(
            "This AI client configuration is a symbolic link. configwarden does not follow "
            "links (they can point outside the project): check what it points to."
        ),
    )


def _mentions_mcp(text: str) -> bool:
    """Le texte brut annonce-t-il des serveurs MCP (même avec des échappements) ?"""
    decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return any(marker in decoded for marker in _MCP_MARKERS)


# Une chaîne JSON complète, puis le « : » qui en fait une clé. On parcourt les
# chaînes ENTIÈRES, sans jamais redémarrer au milieu de l'une d'elles : temps
# linéaire, même avec des milliers de « \\" ». Le texte a déjà été accepté par
# json.loads, donc chaque guillemet trouvé ici ouvre bien une chaîne. Une chaîne
# peut contenir un saut de ligne brut (lecture tolérante, strict=False) : le motif
# l'accepte, sinon il se décalerait et redeviendrait quadratique.
_JSON_STRING = re.compile(r'"[^"\\]*(?:\\[\s\S][^"\\]*)*"')
_KEY_SEPARATOR = re.compile(r"\s*:")


def _key_lines(text: str) -> dict[str, int]:
    """Numéro de ligne (approximatif) de la 1re apparition de chaque clé JSON.

    Calculé en UNE seule lecture du fichier. Sécurité : relire tout le fichier pour
    chaque serveur coûtait un temps quadratique ; un fichier piégé de quelques
    centaines de Ko bloquait alors le scan pendant plusieurs minutes.
    Les noms écrits avec des échappements (« \\u0073 ») sont décodés.
    """
    lines: dict[str, int] = {}
    line, position = 1, 0
    for match in _JSON_STRING.finditer(text):
        if not _KEY_SEPARATOR.match(text, match.end()):
            continue  # une valeur, pas une clé
        line += text.count("\n", position, match.start())
        position = match.start()
        try:
            key = json.loads(match.group(0))
        except ValueError:
            continue
        lines.setdefault(key, line)
    return lines


def _dig(data: object, *keys: str) -> object:
    """data[k1][k2]… sans jamais lever d'exception (None si le chemin n'existe pas)."""
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _server_groups(data: object, mcp_named: bool) -> list[tuple[str, dict[str, dict]]]:
    """Tous les groupes de serveurs d'un fichier : (précision d'affichage, serveurs)."""
    if not isinstance(data, dict):
        return []
    candidates: list[tuple[str, object]] = [
        ("", data.get("mcpServers")),
        ("", _dig(data, "mcp", "servers")),
        ("", _dig(data, "customizations", "vscode", "mcp", "servers")),
        ("", data.get("context_servers")),
    ]
    if mcp_named:
        candidates.append(("", data.get("servers")))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            candidates.append((f" (project {project_path})", _dig(project, "mcpServers")))
    groups = []
    for label, servers in candidates:
        if isinstance(servers, dict):
            valid = {str(k): v for k, v in servers.items() if isinstance(v, dict)}
            if valid:
                groups.append((label, valid))
    return groups


def _auto_approve_settings(data: object) -> list[tuple[str, str]]:
    """Réglages CW109 trouvés : (clé pour le numéro de ligne, description du réglage).

    Réglages relevés dans la documentation officielle de chaque outil (8 octobre 2026).
    Seules les valeurs exactes comptent (`true` booléen, chaîne précise) : un type
    inattendu est ignoré, jamais une cause de plantage.
    """
    if not isinstance(data, dict):
        return []
    found: list[tuple[str, str]] = []

    def flag(key: str, description: str) -> None:
        found.append((key, description))

    # Claude Code (.claude/settings.json, settings.local.json, ~/.claude/settings.json)
    if data.get("enableAllProjectMcpServers") is True:
        flag(
            "enableAllProjectMcpServers",
            "Claude Code approves every MCP server of the project automatically "
            "(enableAllProjectMcpServers: true)",
        )
    if _dig(data, "permissions", "defaultMode") == "bypassPermissions":
        flag(
            "defaultMode",
            "Claude Code runs every action without asking (permissions.defaultMode: "
            "bypassPermissions)",
        )
    if data.get("skipDangerousModePermissionPrompt") is True:
        flag(
            "skipDangerousModePermissionPrompt",
            "Claude Code skips the confirmation of its dangerous modes "
            "(skipDangerousModePermissionPrompt: true)",
        )
    # VS Code (settings.json : clés « à plat »)
    for key in ("chat.tools.global.autoApprove", "chat.tools.autoApprove"):
        if data.get(key) is True:
            flag(key, f"VS Code approves every tool call without asking ({key}: true)")
    # Zed (settings.json : objets imbriqués)
    if _dig(data, "agent", "always_allow_tool_actions") is True:
        flag(
            "always_allow_tool_actions",
            "Zed runs every tool action without asking (agent.always_allow_tool_actions: true)",
        )
    if _dig(data, "agent", "tool_permissions", "default") == "allow":
        flag(
            "tool_permissions",
            "Zed allows every tool by default (agent.tool_permissions.default: allow)",
        )
    if _dig(data, "session", "trust_all_worktrees") is True:
        flag(
            "trust_all_worktrees",
            "Zed trusts every project folder, so project settings and servers load without a "
            "prompt (session.trust_all_worktrees: true)",
        )
    # Cursor (.cursor/permissions.json et configuration de la ligne de commande)
    allowlist = data.get("mcpAllowlist")
    if isinstance(allowlist, list) and "*:*" in allowlist:
        flag(
            "mcpAllowlist",
            "Cursor lets the agent run every MCP tool without asking (mcpAllowlist: *:*)",
        )
    cli_allow = _dig(data, "permissions", "allow")
    if isinstance(cli_allow, list) and "Mcp(*:*)" in cli_allow:
        flag("allow", "Cursor CLI lets the agent run every MCP tool without asking (Mcp(*:*))")
    # Kiro (réglages de l'éditeur)
    autonomy = data.get("kiroAgent.agentAutonomy")
    if isinstance(autonomy, str) and autonomy.lower() == "autopilot":
        flag(
            "kiroAgent.agentAutonomy",
            "Kiro runs in Autopilot mode: the agent's actions are not confirmed "
            "(kiroAgent.agentAutonomy: Autopilot)",
        )
    return found


def _normalize_server(server: dict) -> dict:
    """Zed (ancien format) : "command": {"path", "args", "env"} -> forme commune."""
    command = server.get("command")
    if not isinstance(command, dict):
        return server
    merged = dict(server)
    merged["command"] = command.get("path")
    for key in ("args", "env"):
        if key in command and key not in server:
            merged[key] = command[key]
    return merged


def _package_is_pinned(runner: str, package: str) -> bool:
    """Version EXACTE ? « ^1.0.0 », « ~1.2 », « 1 », « beta », « >=1 » ne le sont pas."""
    if runner == "uvx":
        return bool(_UV_EXACT_VERSION.fullmatch(package))
    # npm : "@scope/pkg@1.2.3" -> on ignore le "@" initial du scope.
    name_and_version = package[1:] if package.startswith("@") else package
    if "@" not in name_and_version:
        return False
    version = name_and_version.rsplit("@", 1)[1]
    return bool(_NPM_EXACT_VERSION.fullmatch(version))


def _is_broad_path(value: str) -> bool:
    """Racine, lecteur entier ou dossier personnel complet (pas un sous-dossier)."""
    return bool(_BROAD_PATH.fullmatch(_normalize_path(value).replace("\\", "/")))


def _literal_secret(value: str) -> str | None:
    """La partie littérale d'une valeur, ou None si c'est une référence ou un modèle."""
    candidate = value.strip().removeprefix("Bearer ").strip()
    for _ in range(20):  # ${A:-${B:-…}} : on descend, mais jamais indéfiniment
        defaulted = _DEFAULTED_REFERENCE.fullmatch(candidate)
        if defaulted is None:
            break
        candidate = defaulted.group(1).strip()
        if not candidate:
            return None
    if not candidate or _ENV_REFERENCE.fullmatch(candidate) or _PLACEHOLDER.fullmatch(candidate):
        return None
    return candidate


def _has_url_password(value: str) -> bool:
    match = _URL_PASSWORD.search(value)
    return match is not None and _literal_secret(match.group(1)) is not None


def _option_values(args: list[str], flags: set[str]) -> list[str]:
    """Valeurs d'une option, sous les formes « --flag valeur » et « --flag=valeur »."""
    values: list[str] = []
    for index, arg in enumerate(args):
        flag, sep, value = arg.partition("=")
        if flag not in flags:
            continue
        if sep:
            values.append(value)
        elif index + 1 < len(args):
            values.append(args[index + 1])
    return values


def _mount_source(spec: str) -> str:
    """Partie « source » d'un montage : '/:/host:ro' -> '/' ; 'C:\\data:/d' -> 'C:\\data'.

    Gère aussi la syntaxe --mount : 'type=bind,source=/,target=/host' -> '/'.
    """
    if "=" in spec and "," in spec or spec.startswith(("source=", "src=", "type=")):
        for part in spec.split(","):
            key, _, value = part.partition("=")
            if key.strip() in {"source", "src"}:
                return value.strip()
        return ""
    # Lettre de lecteur Windows (« C: ») : le premier « : » n'est pas un séparateur.
    if len(spec) >= 2 and spec[1] == ":" and spec[0].isalpha():
        return spec[:2] + spec[2:].split(":", 1)[0]
    return spec.split(":", 1)[0]


def _is_sensitive_mount(source: str) -> bool:
    normalized = _normalize_path(source)
    if _is_broad_path(normalized) or _CREDENTIAL_FOLDER.search(normalized.replace("\\", "/")):
        return True
    lowered = normalized.lower()
    if "docker.sock" in lowered or "docker_engine" in lowered:
        return True
    return any(
        normalized == root or normalized.startswith(root + "/") for root in _SENSITIVE_MOUNT_SOURCES
    )


def _container_issues(args: list[str]) -> list[str]:
    """Liste lisible des options dangereuses d'un « docker run » / « podman run »."""
    if "run" not in args:
        return []
    issues: list[str] = []
    if "--privileged" in args or "--privileged=true" in args:
        issues.append("--privileged")
    for flag_value in _option_values(args, _HOST_NAMESPACE_FLAGS):
        if flag_value == "host":
            issues.append("a host namespace (=host)")
            break
    for spec in _option_values(args, _MOUNT_FLAGS | {"--mount"}):
        source = _mount_source(spec)
        if source and _is_sensitive_mount(source):
            issues.append(f"a mount of '{source}'")
    for capability in _option_values(args, {"--cap-add"}):
        if capability.upper().removeprefix("CAP_") in _DANGEROUS_CAPABILITIES:
            issues.append(f"--cap-add {capability}")
    for option in _option_values(args, {"--security-opt"}):
        if option.endswith("=unconfined") or option.endswith(":unconfined"):
            issues.append(f"--security-opt {option}")
    return issues


def _package_flags(runner: str) -> set[str]:
    return _UV_PACKAGE_FLAGS if runner == "uvx" else _NPM_PACKAGE_FLAGS


def _options_with_value(runner: str) -> set[str]:
    return _UV_OPTIONS_WITH_VALUE if runner == "uvx" else _NPM_OPTIONS_WITH_VALUE


def _first_positional(runner: str, args: list[str]) -> str | None:
    """1er argument qui n'est ni une option, ni la valeur d'une option."""
    with_value = _options_with_value(runner)
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
        elif arg in with_value:
            skip_next = True
        elif not arg.startswith("-"):
            return arg
    return None


def _package_spec(runner: str, args: list[str]) -> str | None:
    """Le paquet lancé : valeur de --from / --package / -p, sinon 1er argument."""
    explicit = _option_values(args, _package_flags(runner))
    return explicit[0] if explicit else _first_positional(runner, args)


def _untrusted_source(runner: str, args: list[str]) -> str | None:
    """Renvoie la source d'un paquet si elle est hors registre officiel (git, URL…).

    On ne regarde que les paquets installés, pas les arguments transmis au serveur :
    un serveur « fetch » peut légitimement recevoir une URL. Un registre privé
    (--registry, --index-url) n'est pas un paquet et n'est pas signalé ici.
    """
    candidates = _option_values(args, _package_flags(runner) | _EXTRA_PACKAGE_FLAGS)
    first = _first_positional(runner, args)
    if first:
        candidates.append(first)
    for value in candidates:
        source = _source_outside_registry(runner, value)
        if source:
            return source
    return None


def _source_outside_registry(runner: str, value: str) -> str | None:
    """L'adresse d'où vient le paquet s'il ne vient pas du registre officiel."""
    if value.lower().startswith(_UNTRUSTED_SOURCE_PREFIXES):
        return value
    pep508 = _PEP508_URL.fullmatch(value)
    if pep508 and pep508.group(1).lower().startswith(_UNTRUSTED_SOURCE_PREFIXES):
        return pep508.group(1)
    scp = _SCP_GIT.fullmatch(value)
    if scp and scp.group(1).lower() != "npm":  # « alias@npm:paquet » reste le registre
        return value.split("@", 1)[1]  # sans la partie « utilisateur@ »
    is_archive = value.lower().endswith((".tgz", ".tar.gz", ".tar"))
    if runner != "uvx" and _GITHUB_SHORTHAND.fullmatch(value) and not is_archive:
        return value
    return None


def _http_host(url: str) -> str | None:
    """Hôte d'une URL en http:// ('' si illisible), ou None si l'URL n'est pas en http://."""
    url = url.strip()
    if not url.lower().startswith("http://"):
        return None
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        # Sécurité : URL malformée (peut-être exprès). On la signale quand même, sans
        # recopier l'URL ni le message d'erreur : ils peuvent contenir un mot de passe.
        return ""


def _check_server(name: str, server: dict, line: int, path: str) -> list[Finding]:
    findings: list[Finding] = []
    command = server.get("command")
    raw_args = server.get("args")
    args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []

    def add(rule: Rule, message: str) -> None:
        findings.append(Finding(rule=rule, path=path, line=line, message=message))

    if isinstance(command, str) and command.strip():
        # Les enveloppes (cmd /c, wsl, env, sudo, bash -c…) sont retirées : on vérifie
        # le programme vraiment lancé, et on relève au passage les risques CW101.
        launch = commands.analyse(command, args)
        exe, args = launch.executable, launch.args

        # CW101 : shell, ligne de commande ou code en ligne (une seule alerte par serveur)
        if launch.risks:
            add(SHELL_EXECUTION, f"Server '{name}' {launch.risks[0]}.")

        if exe in _PACKAGE_RUNNERS:
            # CW107 : paquet hors registre (git, URL…). Plus grave qu'CW102, qu'on ne
            # signale pas en plus pour éviter deux alertes sur la même ligne.
            source = _untrusted_source(exe, args)
            if source:
                # Seulement « schéma://hôte/… » : le chemin ou les paramètres d'une URL
                # peuvent contenir un jeton, même sans « user:token@ ».
                add(
                    UNTRUSTED_PACKAGE_SOURCE,
                    f"Server '{name}' installs its code from '{url_origin(source)}' "
                    "instead of a registry.",
                )
            else:
                # CW102 : paquet non figé
                package = _package_spec(exe, args)
                if package and not _package_is_pinned(exe, package):
                    add(
                        UNPINNED_PACKAGE,
                        f"Server '{name}' runs '{redact_url(package)}' without a pinned version.",
                    )

        # CW106 : conteneur qui casse son isolation
        if exe in _CONTAINER_ENGINES:
            for issue in _container_issues(args):
                add(DANGEROUS_CONTAINER, f"Server '{name}' runs a container with {issue}.")

        # CW104 : accès disque trop large (serveur "filesystem")
        if any("filesystem" in a.lower() for a in args):
            for arg in args:
                if _is_broad_path(arg):
                    add(BROAD_FILESYSTEM, f"Server '{name}' exposes '{arg}' to the AI agent.")

    # CW103 : secrets en dur dans env / headers
    for block_name in ("env", "headers"):
        block = server.get(block_name)
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if not isinstance(value, str) or not value.strip():
                continue
            # Mot de passe dans une URL (DATABASE_URL…), quel que soit le nom de la clé.
            if _has_url_password(value):
                add(
                    HARDCODED_ENV_SECRET,
                    f"Server '{name}' sets {block_name}.{key} to a URL with an embedded "
                    f"password ({url_origin(value)}).",
                )
                continue
            if not _SENSITIVE_KEY.search(str(key)):
                continue
            # Références (${TOKEN}, %TOKEN%…), modèles (<YOUR_KEY>) : pas des secrets.
            if _literal_secret(value) is None:
                continue
            add(
                HARDCODED_ENV_SECRET,
                f"Server '{name}' sets {block_name}.{key} to a literal value ({redact(value)}).",
            )

    # CW105 : serveur distant en HTTP non chiffré (« url », « serverUrl » ou « httpUrl »)
    reported_hosts: set[str] = set()
    for url_key in _URL_KEYS:
        url = server.get(url_key)
        if not isinstance(url, str):
            continue
        host = _http_host(url)
        if host is not None and host not in _LOCAL_HOSTS and host not in reported_hosts:
            reported_hosts.add(host)
            shown = host or "an unreadable address"
            add(INSECURE_TRANSPORT, f"Server '{name}' connects to {shown} over HTTP.")

    # CW108 : outils exécutés sans confirmation de l'utilisateur
    for key in _AUTO_APPROVE_KEYS:
        tools = server.get(key)
        if isinstance(tools, list) and tools:
            listed = ", ".join(str(t) for t in tools[:3]) + ("…" if len(tools) > 3 else "")
            add(
                AUTO_APPROVED_TOOLS,
                f"Server '{name}' lets the agent run {len(tools)} tool(s) "
                f"without asking ({key}: {listed}).",
            )
    if server.get("trust") is True:
        add(AUTO_APPROVED_TOOLS, f"Server '{name}' is fully trusted (trust: true).")

    return findings


def check_text(text: str, path: str, *, mcp_named: bool | None = None) -> list[Finding]:
    """Analyse un fichier JSON (ou JSONC) qui peut contenir des serveurs MCP.

    `mcp_named` : le fichier porte-t-il un nom propre à MCP ? Par défaut, déduit du
    chemin. Un fichier MCP illisible est signalé ; un autre fichier JSON illisible
    reste silencieux (ce n'est probablement pas une configuration MCP).
    """
    if mcp_named is None:
        mcp_named = is_mcp_config(PurePosixPath(path))
    try:
        data, parsed_text = jsonc.loads(text)
    except json.JSONDecodeError as error:
        # Un fichier JSON ordinaire illisible reste silencieux… sauf s'il annonce des
        # serveurs MCP : un outil tolérant aux erreurs pourrait quand même les lancer.
        if not mcp_named and not _mentions_mcp(text):
            return []
        hint = "" if mcp_named else " The file seems to declare MCP servers."
        return [
            Finding(
                rule=INVALID_CONFIG,
                path=path,
                line=error.lineno,
                message=f"Invalid JSON: {error.msg}.{hint}",
            )
        ]
    except (RecursionError, ValueError):
        # Sécurité : un JSON imbriqué à l'extrême (« [[[[…]]]] ») épuise la pile
        # de Python. Sans ce garde-fou, un seul fichier piégé ferait planter
        # tout le scan (déni de service en CI). On le signale comme illisible.
        if not mcp_named and not _mentions_mcp(text):
            return []
        return [
            Finding(
                rule=INVALID_CONFIG,
                path=path,
                line=1,
                message="Invalid JSON: nesting too deep or unreadable content.",
            )
        ]

    groups = _server_groups(data, mcp_named)
    settings = _auto_approve_settings(data)
    if not groups and not settings:
        return []
    # Numéros de ligne calculés sur le texte effectivement lu (commentaires
    # remplacés par des espaces, positions identiques).
    key_lines = _key_lines(parsed_text)
    findings: list[Finding] = [
        Finding(
            rule=CLIENT_AUTO_APPROVE,
            path=path,
            line=key_lines.get(key, 1),
            message=f"{description}.",
        )
        for key, description in settings
    ]
    for label, servers in groups:
        for raw_name, server in servers.items():
            name = raw_name + label
            line = key_lines.get(raw_name, 1)
            try:
                findings.extend(_check_server(name, _normalize_server(server), line, path))
            except Exception:
                # Défense en profondeur : un contenu imprévu dans UN serveur ne doit ni
                # faire planter le scan, ni masquer les problèmes des autres serveurs.
                findings.append(
                    Finding(
                        rule=INVALID_CONFIG,
                        path=path,
                        line=line,
                        message=f"Server '{name}' could not be analysed (unexpected content).",
                    )
                )
    return findings
