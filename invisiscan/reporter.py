"""Report renderers: human table, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

from .detector import ScanResult
from .rules import HIGH, SEVERITY_ORDER

_VERSION = "1.0.0"
_TOOL_URI = "https://github.com/invisiscan/invisiscan"

SARIF_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _unicode_repr(ch: str) -> str:
    """Render a character so it cannot lie to the reader."""
    cp = ord(ch)
    if cp in (0x0A, 0x09, 0x0D):
        return "\\n" if cp == 0x0A else ("\\t" if cp == 0x09 else "\\r")
    cat = __import__("unicodedata").category(ch)
    printable = cat not in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn")
    visible = ch if printable else "<invisible>"
    return "U+{:04X} '{}'".format(cp, visible)


def _severity_counts(results: Sequence[ScanResult]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for res in results:
        for finding in res.findings:
            counts[finding.severity] += 1
        counts["high"] += len(res.confusables)
    return counts


def render_text(results: Sequence[ScanResult], show_context: bool = False) -> str:
    out: List[str] = []
    total = 0
    for res in results:
        if res.error:
            out.append("!! {} :: {}".format(res.path, res.error))
            total += 1
            continue
        if res.clean:
            continue
        sev = res.max_severity()
        out.append("")
        out.append("{}  ({} line(s), max severity: {})".format(res.path, res.lines, sev))
        for finding in res.findings:
            total += 1
            out.append(
                "  [{}] {}:{} {:<38} {}".format(
                    finding.severity.upper(),
                    finding.line,
                    finding.column,
                    "{} ({})".format(finding.rule.rule_id, finding.rule.name),
                    _unicode_repr(finding.char),
                )
            )
        for group in res.confusables:
            total += 1
            variants = ", ".join(sorted(group.variants.keys()))
            locs = sorted({loc for s in group.variants.values() for loc in s})
            out.append(
                "  [HIGH] IS010 (confusable-identifier) skeleton={!r} variants=[{}] at {}".format(
                    group.skeleton, variants, ", ".join(locs)
                )
            )

    counts = _severity_counts(results)
    scanned = len(results)
    dirty = sum(1 for r in results if not r.clean)
    out.append("")
    out.append("-" * 72)
    out.append(
        "Scanned {} file(s), {} file(s) with findings, {} total finding(s)".format(scanned, dirty, total)
    )
    out.append(
        "  critical: {}   high: {}   medium: {}   low: {}".format(
            counts["critical"], counts["high"], counts["medium"], counts["low"]
        )
    )
    return "\n".join(out)


def to_dict(results: Sequence[ScanResult]) -> Dict[str, Any]:
    findings = []
    for res in results:
        for finding in res.findings:
            findings.append(finding.to_dict())
        for group in res.confusables:
            findings.append(group.to_dict())
    return {
        "tool": {"name": "invisiscan", "version": _VERSION},
        "summary": {
            "files_scanned": len(results),
            "files_with_findings": sum(1 for r in results if not r.clean),
            "findings": len(findings),
            "by_severity": _severity_counts(results),
        },
        "results": findings,
    }


def render_json(results: Sequence[ScanResult]) -> str:
    return json.dumps(to_dict(results), indent=2, ensure_ascii=False)


def render_sarif(results: Sequence[ScanResult]) -> str:
    """SARIF 2.1.0 so results land directly in the GitHub Security tab."""
    rules_seen: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for res in results:
        for finding in res.findings:
            rid = finding.rule.rule_id
            rules_seen.setdefault(
                rid,
                {
                    "id": rid,
                    "name": finding.rule.name.replace("-", ""),
                    "shortDescription": {"text": finding.rule.name},
                    "fullDescription": {"text": finding.rule.reason},
                    "help": {"text": finding.rule.remediation},
                    "defaultConfiguration": {"level": SARIF_SEVERITY[finding.severity]},
                    "properties": {"tags": ["security", "unicode", finding.severity]},
                },
            )
            sarif_results.append(
                {
                    "ruleId": rid,
                    "level": SARIF_SEVERITY[finding.severity],
                    "message": {"text": finding.describe()},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": res.path},
                                "region": {"startLine": finding.line, "startColumn": finding.column},
                            }
                        }
                    ],
                }
            )
        for group in res.confusables:
            rid = "IS010"
            rules_seen.setdefault(
                rid,
                {
                    "id": rid,
                    "name": "confusableidentifier",
                    "shortDescription": {"text": "confusable-identifier"},
                    "fullDescription": {
                        "text": "Two or more identifiers in this file collapse to the same visual skeleton, "
                        "which allows a reader to mistake one for the other."
                    },
                    "help": {"text": "Rename one variant so no two identifiers share a skeleton."},
                    "defaultConfiguration": {"level": SARIF_SEVERITY[HIGH]},
                    "properties": {"tags": ["security", "unicode", "high"]},
                },
            )
            resolved = list(group.variants.items())[0]
            first_loc = sorted(resolved[1])[0]
            path, line_no = first_loc.split(":")
            sarif_results.append(
                {
                    "ruleId": rid,
                    "level": SARIF_SEVERITY[HIGH],
                    "message": {
                        "text": "Confusable identifiers sharing skeleton {!r}: {}".format(
                            group.skeleton, ", ".join(sorted(group.variants.keys()))
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": path},
                                "region": {"startLine": int(line_no), "startColumn": 1},
                            }
                        }
                    ],
                }
            )

    return json.dumps(
        {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "InvisiScan",
                            "version": _VERSION,
                            "informationUri": _TOOL_URI,
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        },
        indent=2,
        ensure_ascii=False,
    )
