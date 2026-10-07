"""Règles AG1xx : configurations de serveurs MCP dangereuses.

MCP (Model Context Protocol) permet à un agent IA (Claude, Cursor, VS Code…)
d'utiliser des outils externes. Une mauvaise config peut donner à l'IA, ou
à quelqu'un qui la manipule par injection de prompt, un accès bien trop large.

Formats de fichiers reconnus :
  {"mcpServers": {"nom": {...}}}           Claude Desktop, Cursor, .mcp.json
  {"servers": {"nom": {...}}}              VS Code (.vscode/mcp.json)
  {"mcp": {"servers": {"nom": {...}}}}     VS Code (settings.json)
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from urllib.parse import urlparse

from agentguard.models import Finding, Rule, Severity
from agentguard.redact import redact, redact_url, url_origin

# --- Définition des règles -----------------------------------------------------

INVALID_CONFIG = Rule(
    id="AG100",
    title="Unreadable MCP configuration",
    severity=Severity.LOW,
    remediation="Fix the JSON syntax so the configuration can be audited.",
)
SHELL_EXECUTION = Rule(
    id="AG101",
    title="MCP server runs through a shell",
    severity=Severity.HIGH,
    remediation=(
        "Call the server binary directly instead of `bash -c` / `cmd /c`. A shell "
        "wrapper enables command injection and hides what is really executed."
    ),
)
UNPINNED_PACKAGE = Rule(
    id="AG102",
    title="Unpinned MCP package version",
    severity=Severity.MEDIUM,
    remediation=(
        "Pin an exact version (e.g. `@scope/pkg@1.2.3` or `pkg==1.2.3`). Without it, "
        "a compromised new release would run automatically on your machine."
    ),
)
HARDCODED_ENV_SECRET = Rule(
    id="AG103",
    title="Secret hardcoded in MCP configuration",
    severity=Severity.HIGH,
    remediation=(
        "Reference an environment variable (e.g. `${GITHUB_TOKEN}` or "
        "`${env:GITHUB_TOKEN}`) instead of writing the value in the file."
    ),
)
BROAD_FILESYSTEM = Rule(
    id="AG104",
    title="Overly broad filesystem access",
    severity=Severity.HIGH,
    remediation=(
        "Grant access only to the project folder the agent needs, never the root "
        "or home directory (which contains SSH keys, browser data, .env files…)."
    ),
)
INSECURE_TRANSPORT = Rule(
    id="AG105",
    title="Remote MCP server over plain HTTP",
    severity=Severity.HIGH,
    remediation="Use https:// so tokens and data cannot be intercepted.",
)

DANGEROUS_CONTAINER = Rule(
    id="AG106",
    title="MCP server container escapes isolation",
    severity=Severity.HIGH,
    remediation=(
        "Remove --privileged, host namespaces and mounts of '/', the home directory or the "
        "Docker socket. Mount only the project folder the server needs, read-only if possible."
    ),
)
UNTRUSTED_PACKAGE_SOURCE = Rule(
    id="AG107",
    title="MCP package installed from an unverified source",
    severity=Severity.HIGH,
    remediation=(
        "Install the server from the official registry (npm / PyPI) with a pinned version. "
        "A git repository or URL can change at any time and bypasses registry checks."
    ),
)
AUTO_APPROVED_TOOLS = Rule(
    id="AG108",
    title="MCP tools run without user confirmation",
    severity=Severity.MEDIUM,
    remediation=(
        "Remove `alwaysAllow` / `autoApprove` / `trust: true`, or limit it to read-only tools. "
        "Confirmation is the last barrier against a prompt-injected agent."
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
]

# --- Constantes de détection ---------------------------------------------------

MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
}
_SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"}
_SHELL_EXEC_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-enc"}
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
_ENV_REFERENCE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_:.]*\}?$|^\$\{(env|input):.+\}$")
_BROAD_PATHS = {"/", "~", "$HOME", "${HOME}", "${userHome}", "C:", "%USERPROFILE%"}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104 (liste de comparaison)

# AG106 : moteurs de conteneurs et options qui cassent l'isolation.
_CONTAINER_ENGINES = {"docker", "podman", "nerdctl"}
_HOST_NAMESPACE_FLAGS = {"--network", "--net", "--pid", "--ipc", "--uts", "--userns"}
_MOUNT_FLAGS = {"-v", "--volume"}
_DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN"}
_SENSITIVE_MOUNT_SOURCES = {"/etc", "/root", "/var/run", "/run"}

# AG107 : préfixes qui désignent un paquet hors registre officiel.
_UNTRUSTED_SOURCE_PREFIXES = (
    "git+",
    "git://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "http://",
    "https://",
)

# AG108 : clés qui autorisent des outils sans confirmation, selon le client IA.
_AUTO_APPROVE_KEYS = ("alwaysAllow", "autoApprove")


def _normalize_path(arg: str) -> str:
    """'C:\\' -> 'C:' ; '~/' -> '~' ; '/' reste '/'."""
    return arg.strip().rstrip("/\\") or "/"


def is_mcp_config(path: PurePosixPath) -> bool:
    """Le fichier ressemble-t-il à une configuration MCP ?"""
    name = path.name.lower()
    return name in MCP_CONFIG_NAMES or name.endswith(".mcp.json")


# Une chaîne JSON complète, puis le « : » qui en fait une clé. On parcourt les
# chaînes ENTIÈRES, sans jamais redémarrer au milieu de l'une d'elles : temps
# linéaire, même avec des milliers de « \\" » (le fichier a déjà été validé
# par json.loads, donc chaque guillemet trouvé ici ouvre bien une chaîne).
_JSON_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')
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


def _extract_servers(data: object) -> dict[str, dict]:
    if not isinstance(data, dict):
        return {}
    for candidate in (
        data.get("mcpServers"),
        data.get("servers"),
        (data.get("mcp") or {}).get("servers") if isinstance(data.get("mcp"), dict) else None,
    ):
        if isinstance(candidate, dict):
            return {k: v for k, v in candidate.items() if isinstance(v, dict)}
    return {}


def _executable_name(command: str) -> str:
    """'/usr/bin/bash' -> 'bash' ; 'C:\\...\\cmd.exe' -> 'cmd'."""
    name = re.split(r"[\\/]", command.strip())[-1].lower()
    return name.removesuffix(".exe")


def _package_is_pinned(runner: str, package: str) -> bool:
    if runner == "uvx":
        return "==" in package or ("@" in package and not package.endswith("@latest"))
    # npm : "@scope/pkg@1.2.3" -> on ignore le "@" initial du scope.
    name_and_version = package[1:] if package.startswith("@") else package
    if "@" not in name_and_version:
        return False
    version = name_and_version.rsplit("@", 1)[1]
    return bool(version) and version not in {"latest", "next", "*"}


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
    if normalized in _BROAD_PATHS:
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
        if value.lower().startswith(_UNTRUSTED_SOURCE_PREFIXES):
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
        exe = _executable_name(command)

        # AG101 : exécution via un shell
        if exe in _SHELLS and any(a.lower() in _SHELL_EXEC_FLAGS for a in args):
            add(SHELL_EXECUTION, f"Server '{name}' executes commands through '{exe}'.")

        if exe in _PACKAGE_RUNNERS:
            # AG107 : paquet hors registre (git, URL…). Plus grave qu'AG102, qu'on ne
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
                # AG102 : paquet non figé
                package = _package_spec(exe, args)
                if package and not _package_is_pinned(exe, package):
                    add(
                        UNPINNED_PACKAGE,
                        f"Server '{name}' runs '{redact_url(package)}' without a pinned version.",
                    )

        # AG106 : conteneur qui casse son isolation
        if exe in _CONTAINER_ENGINES:
            for issue in _container_issues(args):
                add(DANGEROUS_CONTAINER, f"Server '{name}' runs a container with {issue}.")

        # AG104 : accès disque trop large (serveur "filesystem")
        if any("filesystem" in a.lower() for a in args):
            for arg in args:
                if _normalize_path(arg) in _BROAD_PATHS:
                    add(BROAD_FILESYSTEM, f"Server '{name}' exposes '{arg}' to the AI agent.")

    # AG103 : secrets en dur dans env / headers
    for block_name in ("env", "headers"):
        block = server.get(block_name)
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if not isinstance(value, str) or not value.strip():
                continue
            if not _SENSITIVE_KEY.search(str(key)):
                continue
            # "Bearer ${TOKEN}" -> on vérifie la partie après "Bearer "
            candidate = value.strip().removeprefix("Bearer ").strip()
            if _ENV_REFERENCE.match(candidate):
                continue
            add(
                HARDCODED_ENV_SECRET,
                f"Server '{name}' sets {block_name}.{key} to a literal value ({redact(value)}).",
            )

    # AG105 : serveur distant en HTTP non chiffré
    url = server.get("url") or server.get("serverUrl")
    if isinstance(url, str):
        host = _http_host(url)
        if host is not None and host not in _LOCAL_HOSTS:
            shown = host or "an unreadable address"
            add(INSECURE_TRANSPORT, f"Server '{name}' connects to {shown} over HTTP.")

    # AG108 : outils exécutés sans confirmation de l'utilisateur
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


def check_text(text: str, path: str) -> list[Finding]:
    """Analyse le contenu d'un fichier de configuration MCP."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        return [
            Finding(
                rule=INVALID_CONFIG,
                path=path,
                line=error.lineno,
                message=f"Invalid JSON: {error.msg}.",
            )
        ]
    except (RecursionError, ValueError):
        # Sécurité : un JSON imbriqué à l'extrême (« [[[[…]]]] ») épuise la pile
        # de Python. Sans ce garde-fou, un seul fichier piégé ferait planter
        # tout le scan (déni de service en CI). On le signale comme illisible.
        return [
            Finding(
                rule=INVALID_CONFIG,
                path=path,
                line=1,
                message="Invalid JSON: nesting too deep or unreadable content.",
            )
        ]

    key_lines = _key_lines(text)
    findings: list[Finding] = []
    for name, server in _extract_servers(data).items():
        line = key_lines.get(name, 1)
        try:
            findings.extend(_check_server(name, server, line, path))
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
