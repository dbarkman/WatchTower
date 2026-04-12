"""Memory and swap check — alert on high swap usage."""
import subprocess

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def _parse_free() -> dict:
    """Parse `free -b` output into bytes."""
    out = subprocess.run(["free", "-b"], capture_output=True, text=True, timeout=5)
    lines = out.stdout.strip().splitlines()
    mem_parts = lines[1].split()
    result = {
        "mem_total": int(mem_parts[1]),
        "mem_used": int(mem_parts[2]),
        "mem_available": int(mem_parts[6]),
    }
    if len(lines) > 2:
        swap_parts = lines[2].split()
        result["swap_total"] = int(swap_parts[1])
        result["swap_used"] = int(swap_parts[2])
    return result


def run(config: dict) -> list[CheckResult]:
    swap_warn_pct = config.get("swap_warn_pct", 50)
    swap_critical_pct = config.get("swap_critical_pct", 80)

    try:
        mem = _parse_free()
    except Exception as e:
        return [CheckResult("Memory", WARNING, f"Failed to read memory: {e}")]

    mem_total_mb = mem["mem_total"] // (1024 * 1024)
    mem_avail_mb = mem["mem_available"] // (1024 * 1024)
    swap_total = mem.get("swap_total", 0)
    swap_used = mem.get("swap_used", 0)

    parts = [f"RAM {mem_avail_mb}/{mem_total_mb} MB available"]
    status = OK

    if swap_total > 0:
        swap_pct = round(swap_used / swap_total * 100)
        swap_used_mb = swap_used // (1024 * 1024)
        swap_total_mb = swap_total // (1024 * 1024)
        parts.append(f"Swap {swap_pct}% ({swap_used_mb}/{swap_total_mb} MB)")

        if swap_pct >= swap_critical_pct:
            status = CRITICAL
        elif swap_pct >= swap_warn_pct:
            status = WARNING
    else:
        parts.append("No swap")

    return [CheckResult("Memory", status, " | ".join(parts))]
