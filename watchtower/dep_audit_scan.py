"""Dependency vulnerability scan — pip-audit for Python projects, npm audit for Node.

Runs WEEKLY (slow: a network call per project) and writes its results to a JSON
state file. The daily report's dep_audit check reads that file, so the report
never blocks on the scan and always shows the most recent result.

    python -m watchtower.dep_audit_scan [--root /var/www/html] [--out <path>]

Projects are auto-discovered so a newly deployed app is picked up without a
config edit:
    uv.lock          -> Python, audited with `uv export | pip-audit`
    package-lock.json -> Node, audited with `npm audit`
A Node project with no lockfile is skipped (npm audit cannot run without one).

Findings separate FIXABLE from unfixable: one needs ten minutes, the other needs
a decision, and conflating them buries the decision.
"""
import argparse
import json
import os
import subprocess
import tempfile
import time

UV = "/usr/local/bin/uv"
UVX = "/usr/local/bin/uvx"
NPM = "/usr/bin/npm"
CACHE = "/var/cache/uv"
DEFAULT_OUT = "/var/www/html/WatchTower/state/dep_audit.json"


def _run(cmd, cwd=None, timeout=300):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def audit_python(path: str) -> dict:
    """pip-audit against the project's resolved lockfile."""
    fd, req = tempfile.mkstemp(suffix=".txt", prefix="wt-req-")
    os.close(fd)
    try:
        ex = _run([UV, "export", "--no-hashes", "--no-header",
                   "--no-emit-project", "--cache-dir", CACHE, "-o", req], cwd=path)
        if ex.returncode != 0:
            return {"error": f"uv export failed: {ex.stderr.strip()[:200]}"}

        au = _run([UVX, "--cache-dir", CACHE, "pip-audit", "--disable-pip",
                   "--no-deps", "-r", req, "--format", "json"], cwd=path)
        # pip-audit exits 1 when vulns are found — that is a result, not an error
        if au.returncode not in (0, 1) or not au.stdout.strip():
            return {"error": f"pip-audit failed: {(au.stderr or au.stdout).strip()[:200]}"}

        data = json.loads(au.stdout)
        findings = []
        for dep in data.get("dependencies", []):
            for v in dep.get("vulns", []):
                fixes = v.get("fix_versions") or []
                findings.append({
                    "package": dep.get("name"),
                    "installed": dep.get("version"),
                    "id": v.get("id"),
                    "fix": fixes[0] if fixes else None,
                })
        return {"findings": findings}
    finally:
        try:
            os.unlink(req)
        except OSError:
            pass


def audit_node(path: str) -> dict:
    """npm audit against the project's package-lock.json."""
    au = _run([NPM, "audit", "--json"], cwd=path)
    if not au.stdout.strip():
        return {"error": f"npm audit produced no output: {au.stderr.strip()[:200]}"}
    try:
        data = json.loads(au.stdout)
    except json.JSONDecodeError:
        return {"error": "npm audit returned unparseable JSON"}

    findings = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        fix = v.get("fixAvailable")
        fix_ver = fix.get("version") if isinstance(fix, dict) else (
            "available" if fix else None)
        findings.append({
            "package": name,
            "installed": v.get("range"),
            "id": v.get("severity", "unknown"),
            "fix": fix_ver,
        })
    return {"findings": findings}


def discover(root: str) -> list[dict]:
    projects = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if not os.path.isdir(p):
            continue
        if os.path.exists(os.path.join(p, "uv.lock")):
            projects.append({"name": name, "type": "python", "path": p})
        elif os.path.exists(os.path.join(p, "package-lock.json")):
            projects.append({"name": name, "type": "node", "path": p})
    return projects


def main():
    ap = argparse.ArgumentParser(description="WatchTower dependency vulnerability scan")
    ap.add_argument("--root", default="/var/www/html")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    results = []
    for proj in discover(args.root):
        r = audit_python(proj["path"]) if proj["type"] == "python" \
            else audit_node(proj["path"])
        entry = {"name": proj["name"], "type": proj["type"]}
        entry.update(r)
        f = r.get("findings")
        if f is not None:
            entry["total"] = len(f)
            entry["fixable"] = sum(1 for x in f if x.get("fix"))
        results.append(entry)
        print(f"{proj['name']:<30} {proj['type']:<7} "
              f"{r.get('error') or str(entry.get('total')) + ' vuln(s)'}")

    out = {"generated": time.time(), "projects": results}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"\nwrote {args.out}")

    # Exit non-zero only if a scan could not RUN — findings are a result, not a failure.
    return 1 if any("error" in r for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
