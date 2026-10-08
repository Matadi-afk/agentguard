"""Analyse de la ligne de commande d'un serveur MCP : enveloppes, shells, code en ligne.

Un serveur est souvent lancé à travers une « enveloppe » : `cmd /c npx …` (Windows),
`wsl …`, `env VAR=1 …`, `sudo …`, `bash -c "…"`. Pour vérifier le programme qui
tourne VRAIMENT (paquet figé ? source fiable ?), on retire ces enveloppes une à une.

Au passage, on relève ce qui permet d'exécuter n'importe quoi (règle CW101) :
- un shell qui reçoit un script (`bash -c`, `sh -lc`, `pwsh -Command`…) ;
- `cmd /c` avec une ligne de commande (un seul texte, ou des caractères spéciaux
  & | < > ^ % !) ; `cmd /c` qui lance un programme en morceaux séparés est accepté
  (décision du 8 octobre 2026 : c'est la méthode des guides officiels sous Windows) ;
- du code écrit dans la configuration (`node -e`, `python -c`…).

Sécurité : chaque étape consomme au moins un mot, donc l'analyse se termine
toujours, en temps linéaire, même avec des milliers d'enveloppes. Un script n'est
découpé que sur ses 10 000 premiers caractères, et au plus 5 fois (imbrication).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

_WINDOWS_SUFFIXES = (".exe", ".cmd", ".bat", ".com")

# Enveloppes et leurs options suivies d'une valeur.
_WRAPPER_OPTIONS_WITH_VALUE: dict[str, set[str]] = {
    "env": {"-u", "--unset", "-C", "--chdir"},
    "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-D", "--chdir"},
    "doas": {"-u", "-C"},
    "wsl": {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "nohup": set(),
    "time": set(),
}
_DURATION = re.compile(r"\d+(?:\.\d+)?[smhd]?")

_POSIX_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_POSIX_OPTIONS_WITH_VALUE = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
_POWERSHELLS = {"powershell", "pwsh"}
_CMD_EXEC_FLAGS = {"/c", "/k", "/r"}
_CMD_METACHARACTERS = frozenset("&|<>^%!")
_SHELL_OPERATORS = frozenset(";&|()<>")

# Code écrit directement dans la configuration : options par interpréteur, et
# options suivies d'une valeur (pour ne pas prendre cette valeur pour un script).
_INLINE_CODE_FLAGS: dict[str, set[str]] = {
    "node": {"-e", "--eval", "-p", "--print"},
    "bun": {"-e", "--eval", "-p", "--print"},
    "python": {"-c"},
    "ruby": {"-e"},
    "perl": {"-e", "-E"},
    "php": {"-r"},
}
_INTERPRETER_OPTIONS_WITH_VALUE: dict[str, set[str]] = {
    "node": {"-r", "--require", "--import", "--loader", "--experimental-loader"},
    "bun": {"-r", "--preload"},
    "python": {"-X", "-W"},
}

_SCRIPT_LIMIT = 10_000
_MAX_SCRIPTS = 5
_MAX_WORDS = 200


@dataclass
class Launch:
    """Résultat de l'analyse : la commande vraiment lancée et les risques CW101."""

    tokens: list[str]
    risks: list[str] = field(default_factory=list)

    @property
    def executable(self) -> str:
        return executable_name(self.tokens[0]) if self.tokens else ""

    @property
    def args(self) -> list[str]:
        return self.tokens[1:]


def _short(text: str, limit: int = 60) -> str:
    """Raccourcit un mot repris dans un message (un nom piégé peut faire 1 Mo)."""
    return text if len(text) <= limit else text[:limit] + "…"


def executable_name(command: str) -> str:
    """'/usr/bin/bash' -> 'bash' ; 'C:\\...\\npx.CMD' -> 'npx'."""
    name = re.split(r"[\\/]", command.strip())[-1].lower()
    for suffix in _WINDOWS_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _interpreter(executable: str) -> str | None:
    if executable in {"node", "nodejs"}:
        return "node"
    if re.fullmatch(r"python[0-9.]*|py", executable):
        return "python"
    return executable if executable in _INLINE_CODE_FLAGS else None


def _after_wrapper(wrapper: str, tokens: list[str], index: int) -> int:
    """Position du programme lancé par une enveloppe (après ses options)."""
    with_value = _WRAPPER_OPTIONS_WITH_VALUE[wrapper]
    duration_seen = False
    while index < len(tokens):
        arg = tokens[index]
        if arg == "--":
            return index + 1
        if arg in with_value:
            index += 2
        elif arg.startswith("-") and len(arg) > 1:
            index += 1
        elif wrapper == "env" and "=" in arg and not arg.startswith("="):
            index += 1  # VARIABLE=valeur
        elif wrapper == "timeout" and not duration_seen and _DURATION.fullmatch(arg):
            duration_seen = True
            index += 1
        else:
            return index
    return index


def _cmd_command(tokens: list[str], index: int) -> tuple[int, str] | None:
    """`cmd /d /s /c …` : position de la commande lancée, et l'option utilisée."""
    while index < len(tokens):
        arg = tokens[index]
        if arg.lower() in _CMD_EXEC_FLAGS:
            return index + 1, arg
        if not arg.startswith("/"):
            return None
        index += 1  # /d, /s, /q, /e:on…
    return None


def _posix_script(tokens: list[str], index: int) -> tuple[str, str] | None:
    """`bash [options] -c script` : (option, script), ou None (fichier de script)."""
    while index < len(tokens):
        arg = tokens[index]
        if arg in _POSIX_OPTIONS_WITH_VALUE:
            index += 2
        elif arg == "--" or not arg.startswith(("-", "+")) or len(arg) == 1:
            return None  # le 1er argument positionnel est un fichier de script
        elif arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            script = tokens[index + 1] if index + 1 < len(tokens) else ""
            return arg, script
        else:
            index += 1
    return None


def _powershell_command(tokens: list[str], index: int) -> tuple[str, str, bool] | None:
    """`pwsh -Command …` / `-EncodedCommand …` : (option, script, encodé ?)."""
    while index < len(tokens):
        arg = tokens[index]
        option = "-" + arg[1:].lower() if arg.startswith(("-", "/")) else ""
        if option in {"-file", "-f"}:
            return None  # la suite appartient au script lancé
        if len(option) >= 2:
            # PowerShell accepte tout début non ambigu : -e, -enc, -ec, -c, -com…
            if option == "-ec" or "-encodedcommand".startswith(option):
                return arg, "", True
            if "-command".startswith(option):
                return arg, " ".join(tokens[index + 1 :]), False
        index += 1
    return None


def _inline_code(interpreter: str, executable: str, tokens: list[str], index: int) -> str | None:
    """Option de code en ligne (`node -e`, `python -c`…) avant tout fichier de script."""
    flags = _INLINE_CODE_FLAGS[interpreter]
    with_value = _INTERPRETER_OPTIONS_WITH_VALUE.get(interpreter, set())
    while index < len(tokens):
        arg = tokens[index]
        option = arg.split("=", 1)[0] if arg.startswith("--") else arg
        if option in flags:
            return f"{_short(executable)} {option}"
        if interpreter == "python":
            if arg == "-m":
                return None  # module : la suite lui appartient
            if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", arg):
                return f"{_short(executable)} {_short(arg)}"  # options groupées : python -Bc
        if arg in with_value:
            index += 2
            continue
        if not arg.startswith("-"):
            return None  # fichier de script
        index += 1
    return None


def _first_command(words: list[str]) -> list[str]:
    """Mots de la 1re commande d'un script (jusqu'au premier opérateur ; & | …)."""
    result: list[str] = []
    for word in words:
        if word and set(word) <= _SHELL_OPERATORS:
            break
        result.append(word.strip("'\""))
        if len(result) >= _MAX_WORDS:
            break
    return result


def _split_posix(script: str) -> list[str]:
    script = script[:_SCRIPT_LIMIT]
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words: list[str] = []
        for word in lexer:
            words.append(word)
            if len(words) > _MAX_WORDS or (word and set(word) <= _SHELL_OPERATORS):
                break
        return _first_command(words)
    except ValueError:
        # Guillemet jamais fermé : découpage simple, sans planter.
        return _first_command(re.split(r"[;&|]", script, maxsplit=1)[0].split())


def _split_windows(text: str) -> list[str]:
    text = text[:_SCRIPT_LIMIT]
    words = re.findall(r'"[^"]*"|[&|<>]+|[^\s"&|<>]+', text)
    return _first_command(words[: _MAX_WORDS + 1])


def _metacharacters_from(tokens: list[str]) -> list[bool]:
    """flags[i] : un caractère spécial de cmd apparaît-il dans tokens[i:] ?

    Calculé une fois par liste (en partant de la fin) : vérifier la suite à chaque
    `cmd /c` imbriqué coûterait un temps quadratique sur une chaîne piégée.
    """
    flags = [False] * (len(tokens) + 1)
    for index in range(len(tokens) - 1, -1, -1):
        flags[index] = flags[index + 1] or bool(_CMD_METACHARACTERS & set(tokens[index]))
    return flags


def analyse(command: str, args: list[str]) -> Launch:
    """Retire les enveloppes et relève les risques CW101 d'une ligne de commande."""
    tokens = [command, *args]
    start = 0
    risks: list[str] = []
    scripts = 0
    metacharacters: list[bool] | None = None
    while start < len(tokens):
        executable = executable_name(tokens[start])
        if executable in _WRAPPER_OPTIONS_WITH_VALUE:
            start = _after_wrapper(executable, tokens, start + 1)
            continue
        if executable == "cmd":
            found = _cmd_command(tokens, start + 1)
            if found is None:
                break
            inner_start, flag = found
            single_text = len(tokens) - inner_start == 1 and any(
                c.isspace() for c in tokens[inner_start]
            )
            if metacharacters is None:
                metacharacters = _metacharacters_from(tokens)
            if single_text or metacharacters[inner_start]:
                risks.append(f"executes a command line through 'cmd {_short(flag)}'")
            if single_text and scripts < _MAX_SCRIPTS:
                scripts += 1
                tokens, start, metacharacters = _split_windows(tokens[inner_start]), 0, None
            else:
                start = inner_start
            continue
        if executable in _POSIX_SHELLS:
            found_script = _posix_script(tokens, start + 1)
            if found_script is None:
                break
            flag, script = found_script
            risks.append(f"executes commands through '{_short(executable)} {_short(flag)}'")
            if scripts >= _MAX_SCRIPTS:
                tokens, start = [], 0
                break
            scripts += 1
            tokens, start, metacharacters = _split_posix(script), 0, None
            continue
        if executable in _POWERSHELLS:
            found_ps = _powershell_command(tokens, start + 1)
            if found_ps is None:
                break
            flag, script, encoded = found_ps
            if encoded:
                risks.append(
                    f"executes an encoded command through '{_short(executable)} {_short(flag)}'"
                )
                tokens, start = [], 0
                break
            risks.append(f"executes commands through '{_short(executable)} {_short(flag)}'")
            if scripts >= _MAX_SCRIPTS:
                tokens, start = [], 0
                break
            scripts += 1
            tokens, start, metacharacters = _split_windows(script), 0, None
            continue
        interpreter = _interpreter(executable)
        if interpreter is not None:
            inline = _inline_code(interpreter, executable, tokens, start + 1)
            if inline is not None:
                risks.append(f"executes inline code ('{inline}')")
        elif executable == "deno" and start + 1 < len(tokens) and tokens[start + 1] == "eval":
            risks.append("executes inline code ('deno eval')")
        break
    return Launch(tokens=tokens[start:], risks=risks)
