#!/usr/bin/env python3
"""Generate CVE recipe pages from a local GitHub Advisory Database checkout.

Usage:
  python scripts/generate_cve_recipes_from_ghad.py \
    --advisory-root /path/to/advisory-database/advisories/github-reviewed \
    --output-root content/prompt-library/cve/generated
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path

SEVERITIES = {"high", "critical"}


def slugify(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:48] or "advisory"


def has_fix(affected: list[dict]) -> bool:
    return any(
        "fixed" in event
        for item in affected
        for rng in item.get("ranges", [])
        for event in rng.get("events", [])
    )


def fixed_versions(affected: list[dict]) -> list[str]:
    values = {
        event["fixed"]
        for item in affected
        for rng in item.get("ranges", [])
        for event in rng.get("events", [])
        if "fixed" in event
    }
    return sorted(values)


def affected_ranges(affected: list[dict]) -> list[str]:
    rows: list[str] = []
    for item in affected:
        pkg = item.get("package", {})
        name = pkg.get("name", "unknown-package")
        eco = pkg.get("ecosystem", "unknown")
        for rng in item.get("ranges", []):
            introduced = None
            fixed = None
            for event in rng.get("events", []):
                introduced = event.get("introduced", introduced)
                fixed = event.get("fixed", fixed)
            if introduced is not None and fixed:
                rows.append(f"- **{name} ({eco})**: `>={introduced}, <{fixed}`")
            elif fixed:
                rows.append(f"- **{name} ({eco})**: `<{fixed}`")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--advisory-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--author", default="Codex")
    parser.add_argument("--team", default="Security")
    args = parser.parse_args()

    args.output_root.mkdir(parents=True, exist_ok=True)

    today = dt.date.today().isoformat()
    generated = 0
    skipped = 0

    for json_path in args.advisory_root.rglob("*.json"):
        try:
            advisory = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            skipped += 1
            continue

        severity = (advisory.get("database_specific", {}).get("severity") or "").lower()
        if severity not in SEVERITIES:
            continue

        aliases = advisory.get("aliases", [])
        cves = [a for a in aliases if a.startswith("CVE-")]
        if not cves:
            continue

        affected = advisory.get("affected", [])
        if not has_fix(affected):
            continue

        cve = cves[0]
        summary = (advisory.get("summary") or f"{cve} security advisory").strip()
        details = (advisory.get("details") or summary).strip().replace("\n\n", "\n")
        if len(details) > 700:
            details = details[:700].rsplit(" ", 1)[0] + "…"

        eco = "unknown"
        for item in affected:
            pkg_eco = item.get("package", {}).get("ecosystem")
            if pkg_eco:
                eco = pkg_eco.lower()
                break

        fixed = fixed_versions(affected)
        fixed_str = ", ".join(fixed[:6]) if fixed else "see advisory"
        ranges = affected_ranges(affected)
        if not ranges:
            continue

        disclosed = (advisory.get("published") or "")[:10] or today
        ghsa_id = advisory.get("id", "unknown")
        slug = slugify(summary)
        path = args.output_root / f"{cve.lower()}-{slug}.md"

        safe_summary = summary.replace('"', "'")
        lines = [
            "---",
            f'title: "{cve} — {safe_summary}"',
            f'linkTitle: "{cve}"',
            f'description: "{safe_summary}"',
            'tool: "general"',
            f'author: "{args.author}"',
            f'team: "{args.team}"',
            'maturity: "draft"',
            'model: "GPT-5.3-Codex"',
            'tags: ["cve", "generated", "github-advisory"]',
            f'weight: {1000 + generated}',
            f'date: {today}',
            f'cve: "{cve}"',
            f'aliases: ["{safe_summary}"]',
            'kev: false',
            f'severity: "{severity}"',
            f'ecosystem: "{eco}"',
            f'disclosed: "{disclosed}"',
            "---",
            "",
            details,
            "",
            "## Affected versions",
            "",
            *ranges,
            "",
            "## Indicator-of-exposure",
            "",
            "You are exposed when any deployable target resolves one of the",
            "affected ranges above in direct or transitive dependencies.",
            "",
            "## Remediation strategy",
            "",
            f"Upgrade to a patched release (minimum observed fixed version(s): `{fixed_str}`).",
            "Regenerate lockfiles, rebuild artifacts, and redeploy affected services.",
            "",
            "## The prompt",
            "",
            "~~~markdown",
            f"You are remediating {cve}.",
            "",
            "1) Detect vulnerable dependency versions in manifests and lockfiles.",
            f"2) Upgrade to patched versions (minimum: {fixed_str}).",
            "3) Run build/tests and dependency scan verification.",
            "4) If no safe upgrade path exists, output TRIAGE.md with blockers and containment.",
            "~~~",
            "",
            "## Verification — what the reviewer looks for",
            "",
            "- No vulnerable versions remain in resolved dependencies.",
            "- Updated lock/state files are committed.",
            "- CI/build/test checks pass.",
            "",
            "## Watch for",
            "",
            "- Hidden transitive copies of the vulnerable package.",
            "- Environment-specific lockfile drift.",
            "",
            "## Sources",
            "",
            f"- GitHub Advisory: `{ghsa_id}`",
            f"- CVE: `{cve}`",
            "",
        ]

        path.write_text("\n".join(lines), encoding="utf-8")
        generated += 1

    print(f"generated={generated} skipped={skipped} output={args.output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
