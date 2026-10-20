"""Host key fingerprints and known_hosts entries.

The fingerprint is the value an administrator compares out of
band before trusting a host key, and the known_hosts entry is
the line written to the trust store.
"""

from __future__ import annotations

import base64
import hashlib

import paramiko

def fingerprint(key: paramiko.PKey) -> str:
    """
    Return the OpenSSH-style SHA-256 fingerprint of a host key.

    Args:
        key: The paramiko host key object.

    Returns:
        A fingerprint string such as
        'SHA256:7f9tLuJMScst0ObcMi3DVb+Rjy/S/lR+gSSHeZq7Pds'.
    """
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

def known_hosts_entry(hostname: str, port: int, key: paramiko.PKey) -> str:
    """
    Build a known_hosts line for the given host and key.

    Non-standard ports use the OpenSSH [host]:port form, matching how
    paramiko looks up keys for them.

    Args:
        hostname: The host name or IP address.
        port: The SSH port.
        key: The host key object.

    Returns:
        A single known_hosts line ending with a newline.
    """
    name = hostname if port == 22 else f"[{hostname}]:{port}"
    return f"{name} {key.get_name()} {key.get_base64()}\n"
