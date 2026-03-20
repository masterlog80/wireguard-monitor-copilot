"""Firewall rules module – reads iptables / nftables rules."""
from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Tuple


def _run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"


def get_iptables_rules() -> Dict[str, Any]:
    """Return iptables rules parsed into sections."""
    tables = ["filter", "nat", "mangle", "raw"]
    result: Dict[str, Any] = {"available": False, "tables": {}}

    for table in tables:
        rc, out, err = _run(["iptables", "-t", table, "-L", "-n", "-v", "--line-numbers"])
        if rc == 0:
            result["available"] = True
            result["tables"][table] = _parse_iptables_output(out)
        else:
            result["tables"][table] = {"error": err.strip() or "Permission denied"}

    return result


def _parse_iptables_output(text: str) -> Dict[str, Any]:
    """Parse ``iptables -L -n -v --line-numbers`` output into chains."""
    chains: Dict[str, List[str]] = {}
    current_chain: str | None = None

    for line in text.splitlines():
        if line.startswith("Chain "):
            # e.g. "Chain INPUT (policy ACCEPT 1234 packets)"
            chain_name = line.split()[1]
            current_chain = chain_name
            chains[current_chain] = []
        elif current_chain is not None and line.strip():
            chains[current_chain].append(line)

    return {"chains": chains}


def get_nftables_rules() -> Dict[str, Any]:
    """Return nftables ruleset as plain text."""
    rc, out, err = _run(["nft", "list", "ruleset"])
    if rc == 0:
        return {"available": True, "ruleset": out}
    return {"available": False, "error": err.strip() or "nft not available"}


def get_firewall_rules() -> Dict[str, Any]:
    """Return combined firewall rules from iptables and nftables."""
    return {
        "iptables": get_iptables_rules(),
        "nftables": get_nftables_rules(),
    }
