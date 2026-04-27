"""Wallet balance check — alert when on-chain balances dip below thresholds.

Uses raw JSON-RPC over `requests` (no web3 dep). Supports native chain coins
(ETH, MATIC) and ERC-20 tokens (USDC, USDC.e) on any EVM chain.

Config example:
    wallets:
      probes:
        - name: "Polygon MATIC (gas)"
          rpc: "https://polygon-bor-rpc.publicnode.com"
          wallet: "0xdff93b80dce6ecb124fc20836d68cbbf9f27c62f"
          decimals: 18
          warn_below: 30
          critical_below: 5
        - name: "Polygon USDC.e (Polymarket)"
          rpc: "https://polygon-bor-rpc.publicnode.com"
          wallet: "0xdff93b80dce6ecb124fc20836d68cbbf9f27c62f"
          token: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
          decimals: 6
          warn_below: 100
          critical_below: 50
"""
import requests

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


# ERC-20 balanceOf(address) selector + 32-byte address arg
_BALANCE_OF_SELECTOR = "0x70a08231"


def _eth_get_balance(rpc: str, wallet: str, timeout: int = 10) -> int | None:
    """Native chain balance (wei-equivalent atomic units)."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [wallet, "latest"],
        "id": 1,
    }
    try:
        r = requests.post(rpc, json=payload, timeout=timeout)
        result = r.json().get("result")
        if not result:
            return None
        return int(result, 16)
    except Exception:
        return None


def _erc20_balance(rpc: str, token: str, wallet: str, timeout: int = 10) -> int | None:
    """ERC-20 token balance via eth_call balanceOf(address)."""
    addr_no_prefix = wallet.lower().removeprefix("0x")
    data = _BALANCE_OF_SELECTOR + ("0" * 24) + addr_no_prefix
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": token, "data": data}, "latest"],
        "id": 1,
    }
    try:
        r = requests.post(rpc, json=payload, timeout=timeout)
        result = r.json().get("result")
        if not result:
            return None
        return int(result, 16)
    except Exception:
        return None


def _format_balance(atomic: int, decimals: int) -> str:
    val = atomic / (10 ** decimals)
    if decimals == 18:
        return f"{val:.4f}"
    return f"{val:.2f}"


def run(config: dict) -> list[CheckResult]:
    probes = config.get("probes", []) or []
    if not probes:
        return [CheckResult("Wallets", OK, "No wallet probes configured")]

    results = []
    parts = []
    worst = OK
    priority = [OK, WARNING, CRITICAL]

    for probe in probes:
        name = probe.get("name", "wallet")
        rpc = probe.get("rpc")
        wallet = probe.get("wallet")
        token = probe.get("token")  # None = native coin
        decimals = int(probe.get("decimals", 18))
        warn_below = float(probe.get("warn_below", 0))
        critical_below = float(probe.get("critical_below", 0))

        if not rpc or not wallet:
            results.append(CheckResult(f"Wallet ({name})", WARNING,
                                       f"missing rpc or wallet"))
            continue

        if token:
            atomic = _erc20_balance(rpc, token, wallet)
        else:
            atomic = _eth_get_balance(rpc, wallet)

        if atomic is None:
            results.append(CheckResult(f"Wallet ({name})", WARNING,
                                       "RPC fetch failed"))
            if priority.index(WARNING) > priority.index(worst):
                worst = WARNING
            continue

        balance = atomic / (10 ** decimals)

        if balance < critical_below:
            status = CRITICAL
        elif balance < warn_below:
            status = WARNING
        else:
            status = OK

        if priority.index(status) > priority.index(worst):
            worst = status

        parts.append(f"{name}: {_format_balance(atomic, decimals)}")

        if status != OK:
            results.append(CheckResult(
                f"Wallet ({name})", status,
                f"balance {_format_balance(atomic, decimals)} below "
                f"{'critical' if status == CRITICAL else 'warn'} threshold "
                f"{critical_below if status == CRITICAL else warn_below}",
            ))

    summary = " | ".join(parts) if parts else "no balances reported"
    results.append(CheckResult("Wallets", worst, summary))
    return results
