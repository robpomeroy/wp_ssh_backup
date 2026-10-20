"""Quoting for remote shell commands.

A path that reaches the remote host is attacker-influenced data:
it can contain spaces, quotes and shell metacharacters. These
helpers quote it so the remote shell receives it as exactly one
argument, whatever it contains.
"""

from __future__ import annotations


def shquote(path: str) -> str:
    """
    Single-quote a path for safe use in a remote shell command.

    Args:
        path: The path to be quoted.

    Returns:
        The single-quoted path as a string.
    """
    return "'" + path.replace("'", "'\\''") + "'"

def trap_rm_action(path: str) -> str:
    """
    Build a trap action that removes a file, quoted as one shell argument.

    The path is single-quoted inside the action, and the complete action is
    single-quoted again, so the shell hands trap exactly one argument and
    re-evaluates it safely when the signal fires. Nesting the quotes the
    other way round (quoting the action but letting the path's quotes
    terminate it) splits the action into several arguments: trap then
    rejects the bogus signal name, the cleanup never runs, and shell
    metacharacters in the path would be re-evaluated.

    Args:
        path: The path of the file the trap should remove.

    Returns:
        A fully-quoted trap action, ready for 'trap <action> EXIT'.
    """
    return shquote(f"rm -f {shquote(path)}")
