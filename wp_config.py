"""Parsing wp-config.php on the remote host.

The parser reads the define() calls that carry the database
settings, without executing any PHP and without a full PHP
grammar: it only needs to find the DB_* constants and their
values.
"""

from __future__ import annotations

import posixpath
import re

import paramiko

from errors import MissingArtifactError
from remote import read_remote_file, remote_path_exists

# ---------------------------------------------------------------------------
# wp-config.php parsing
# ---------------------------------------------------------------------------

WP_DB_KEYS = ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST")

# Escape sequences PHP recognises, per string delimiter. Anything else
# keeps its backslash, matching PHP's behaviour.
_SINGLE_ESCAPES = {"'", "\\"}

_DOUBLE_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "f": "\f",
    "e": "\x1b",
    "\\": "\\",
    '"': '"',
    "$": "$",
}

WP_DEFINE_RE = re.compile(
    r"\bdefine\s*\(\s*['\"](?P<name>DB_[A-Za-z_]+)['\"]\s*,\s*"
    r"(?P<q>['\"])(?P<value>(?:\\.|(?!(?P=q)).)*)(?P=q)\s*\)\s*;",
    re.DOTALL,
)


def strip_php_comments(source: str) -> tuple[str, list[bool]]:
    """
    Remove PHP comments from source while preserving string literals.

    A single pass tracks whether the scanner is inside a single- or
    double-quoted string (honouring backslash escapes) or inside a line
    ('//' or '#') or block ('/* ... */') comment. Comment openers are only
    recognised in code, so comment-like text inside string literals — for
    example a password containing '//' or '/*' — is preserved verbatim.
    Each comment is replaced by a single space, mirroring the PHP
    tokenizer, which treats comments as whitespace.

    Args:
        source: The PHP source text.

    Returns:
        A tuple of (stripped, in_string): stripped is the source with
        comments removed, and in_string[i] is True when stripped[i] lies
        inside a string literal. Heredocs and the '?>' HTML mode are not
        tracked; wp-config.php does not use them.
    """
    out: list[str] = []
    in_string: list[bool] = []
    i = 0
    n = len(source)
    state = "code"
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "'":
                state = "single"
                out.append(ch)
                in_string.append(False)
                i += 1
            elif ch == '"':
                state = "double"
                out.append(ch)
                in_string.append(False)
                i += 1
            elif ch == "/" and nxt == "/":
                state = "line"
                out.append(" ")
                in_string.append(False)
                i += 2
            elif ch == "#":
                state = "line"
                out.append(" ")
                in_string.append(False)
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block"
                out.append(" ")
                in_string.append(False)
                i += 2
            else:
                out.append(ch)
                in_string.append(False)
                i += 1
        elif state == "single" or state == "double":
            quote = "'" if state == "single" else '"'
            if ch == "\\" and nxt:
                out.append(ch)
                in_string.append(True)
                out.append(nxt)
                in_string.append(True)
                i += 2
            else:
                if ch == quote:
                    state = "code"
                out.append(ch)
                in_string.append(ch != quote)
                i += 1
        elif state == "line":
            if ch == "\n":
                state = "code"
                out.append(ch)
                in_string.append(False)
            i += 1
        else:  # block comment
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                i += 1
    return "".join(out), in_string

def _unescape_php(value: str, quote: str) -> str:


    r"""
    Decode PHP escape sequences in the raw text of a string literal.

    PHP retains the backslash for escape sequences it does not recognise,
    so 'p\q' denotes p\q rather than pq; only sequences PHP recognises
    are decoded here. Single-quoted strings recognise only \' and \\;
    double-quoted strings additionally recognise \n, \r, \t, \v, \f,
    \e, \$, octal, hex and \u{...} sequences.

    Args:
        value: The raw text between the string delimiters.
        quote: The delimiter the literal was written with (' or ").

    Returns:
        The decoded string value.
    """
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = value[i + 1]
        if quote == "'":
            if nxt in _SINGLE_ESCAPES:
                out.append(nxt)
            else:
                out.append(ch + nxt)
            i += 2
            continue
        simple = _DOUBLE_ESCAPES.get(nxt)
        if simple is not None:
            out.append(simple)
            i += 2
            continue
        if nxt == "x":
            hexa = re.match(r"[0-9A-Fa-f]{1,2}", value[i+2:])
            if hexa:
                out.append(chr(int(hexa.group(0), 16)))
                i += 2 + len(hexa.group(0))
                continue
        elif nxt == "u":
            uni = re.match(r"\{[0-9A-Fa-f]+\}", value[i+2:])
            if uni:
                out.append(chr(int(uni.group(0)[1:-1], 16)))
                i += 2 + len(uni.group(0))
                continue
        elif nxt in "01234567":
            octal = re.match(r"[0-7]{1,2}", value[i+2:])
            digits = 1 + (len(octal.group(0)) if octal else 0)
            octal_value = int(value[i+1:i+1+digits], 8) % 256
            out.append(chr(octal_value))
            # Advance past the backslash and every consumed octal digit;
            # forgetting this leaves i unchanged and loops forever.
            i += 1 + digits
            continue
        # Unrecognised escape: PHP keeps the backslash.
        out.append(ch + nxt)
        i += 2
    return "".join(out)



def parse_wp_config(text: str) -> dict[str, str]:
    """
    Extract WordPress DB connection settings from wp-config.php source.

    PHP comments are removed before definitions are selected, so a
    commented-out define can no longer shadow the real one; comment-like
    text inside string literals is preserved, so values containing '//' or
    '/*' survive intact. A define appearing inside a string literal is not
    treated as code.

    Note:
        Only literal string values are recognised; wp-config files that build
        values dynamically (e.g. from getenv) will yield missing keys, which
        callers report as a clear error. Heredoc strings and the '?>' HTML
        mode are not tracked. Escape sequences are decoded per PHP rules;
        unrecognised escapes keep their backslash.

    Args:
        text: The content of the wp-config.php file as a string.

    Returns:
        A dictionary containing the WordPress DB connection settings, with keys
        being the setting names (e.g., "DB_NAME") and values being the
        corresponding values from the wp-config.php file.
    """
    stripped, in_string = strip_php_comments(text)
    found: dict[str, str] = {}
    for match in WP_DEFINE_RE.finditer(stripped):
        if in_string[match.start()]:
            continue
        name = match.group("name").upper()
        if name in WP_DB_KEYS and name not in found:
            found[name] = _unescape_php(
                match.group("value"), match.group("q")


            )
    return found

def read_wp_db_settings(
    sftp: paramiko.SFTPClient, site_root: str
) -> dict[str, str]:
    """
    Read wp-config.php over SFTP and validate the required DB keys.

    Args:
        sftp: An active Paramiko SFTP client connected to the remote host.
        site_root: The root directory of the WordPress site on the remote host.

    Returns:
        A dictionary containing the WordPress DB connection settings, with keys
        being the setting names (e.g., "DB_NAME") and values being the
        corresponding values from the wp-config.php file.
    """
    wp_config_path = posixpath.join(site_root, "wp-config.php")
    if not remote_path_exists(sftp, wp_config_path):
        raise MissingArtifactError(
            f"{wp_config_path} not found on the remote host; cannot determine "
            "database credentials."
        )
    settings = parse_wp_config(read_remote_file(sftp, wp_config_path))
    missing = [key for key in WP_DB_KEYS if key not in settings]
    if missing:
        raise MissingArtifactError(
            "wp-config.php is missing database setting(s): "
            + ", ".join(missing)
        )
    return settings
