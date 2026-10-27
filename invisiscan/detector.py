"""Core scanning engine.

Scans UTF-8 text files for invisible, look-alike and direction-control
Unicode characters, plus identifier-level confusable (homograph) groups built
with a UTS#39 skeleton index.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Pattern, Sequence, Set, Tuple

from .confusables import is_confusable_candidate, to_confusable_skeleton
from .rules import (
    ALL_RULE_IDS,
    HIGH,
    LOW,
    MEDIUM,
    NONCHARACTER_RULE,
    SEVERITY_ORDER,
    Rule,
    RULE_FOR_CODEPOINT,
    is_noncharacter,
    is_private_use,
)

DEFAULT_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift", ".kt",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".md", ".txt", ".sh",
    ".sql", ".html", ".css", ".scss", ".vue", ".lua", ".pl", ".r", ".scala",
}

# Line-level suppression:  `...  # invisiscan:ignore`              (all rules)
#                         `...  # invisiscan:ignore=IS002,IS010`   (named rules)
SUPPRESSION_RE: Pattern[str] = re.compile(r"invisiscan:ignore(?:=([A-Za-z0-9,_ ]+))?")


@dataclass
class Finding:
    """One detected occurrence."""

    rule: Rule
    line: int
    column: int
    char: str
    codepoint: int
    context: str = ""

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def name(self) -> str:
        return self.char

    def location(self) -> Dict[str, int]:
        return {"line": self.line, "column": self.column}

    def describe(self) -> str:
        try:
            official = unicodedata.name(self.char)
        except ValueError:
            official = "UNKNOWN"
        return "U+{:04X} {}".format(self.codepoint, official)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule": self.rule.rule_id,
            "category": self.rule.name,
            "severity": self.severity,
            "file": self.context,
            "line": self.line,
            "column": self.column,
            "codepoint": "U+{:04X}".format(self.codepoint),
            "character_name": self.describe().split(" ", 1)[1],
            "message": self.rule.reason,
            "remediation": self.rule.remediation,
        }


@dataclass
class ConfusableGroup:
    """A cluster of identifiers that share a visual skeleton."""

    skeleton: str
    variants: Dict[str, Set[str]] = field(default_factory=dict)

    def add(self, word: str, location: Tuple[str, int]) -> None:
        self.variants.setdefault(word, set()).add("{}:{}".format(*location))

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule": "IS010",
            "category": "confusable-identifier",
            "severity": HIGH,
            "skeleton": self.skeleton,
            "variants": sorted(self.variants.keys()),
            "locations": sorted({loc for s in self.variants.values() for loc in s}),
        }


@dataclass
class ScanResult:
    """Aggregate outcome for a single file."""

    path: str
    findings: List[Finding] = field(default_factory=list)
    confusables: List[ConfusableGroup] = field(default_factory=list)
    lines: int = 0
    error: Optional[str] = None

    @property
    def clean(self) -> bool:
        return not self.findings and not self.confusables and self.error is None

    def max_severity(self) -> Optional[str]:
        sev = [f.severity for f in self.findings]
        sev += [HIGH for _ in self.confusables]
        if not sev:
            return None
        return min(sev, key=lambda s: SEVERITY_ORDER[s])

    def sort_findings(self) -> None:
        self.findings.sort(key=lambda f: (f.line, f.column))


class Scanner:
    """Stateful scanner holding configuration and the skeleton index."""

    def __init__(
        self,
        min_severity: str = LOW,
        detect_confusables: bool = True,
        min_word_length: int = 3,
        allow_rules: Optional[Set[str]] = None,
        deny_rules: Optional[Set[str]] = None,
    ) -> None:
        self.min_severity = min_severity
        self.detect_confusables = detect_confusables
        self.min_word_length = min_word_length
        self.allow_rules = allow_rules or set()
        self.deny_rules = deny_rules or set()
        self._skeleton_index: Dict[str, Dict[str, Set[Tuple[str, int]]]] = {}

    # -- rule filtering ---------------------------------------------------
    def _enabled(self, rule: Rule) -> bool:
        if rule.rule_id in self.deny_rules:
            return False
        if self.allow_rules:
            return rule.rule_id in self.allow_rules
        return SEVERITY_ORDER[rule.severity] <= SEVERITY_ORDER[self.min_severity]

    # -- suppression ------------------------------------------------------
    @staticmethod
    def _suppression_for(line: str) -> Optional[Set[str]]:
        """Return the rule ids silenced on this line, or None if none are.

        Recognises ``# invisiscan:ignore`` for everything on the line and
        ``# invisiscan:ignore=IS002,IS010`` for named rules.
        """
        match = SUPPRESSION_RE.search(line)
        if match is None:
            return None
        listed = match.group(1)
        if not listed:
            return set(ALL_RULE_IDS)
        return {token.strip().upper() for token in listed.split(",") if token.strip()}

    # -- per-character scan ----------------------------------------------
    def scan_text(self, text: str, path: str = "<stdin>") -> ScanResult:
        result = ScanResult(path=path)
        # Deliberately NOT str.splitlines(): Python treats U+2028/U+2029/U+0085
        # as line breaks, which would silently swallow exactly the
        # newline-lookalike characters this tool exists to catch. Splitting on
        # "\n" keeps them inside the line where they can be reported.
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        result.lines = len(lines)

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
            line_findings: List[Finding] = []
            col = 0
            for ch in line:
                col += 1
                cp = ord(ch)
                rule = RULE_FOR_CODEPOINT.get(cp)
                if rule is not None:
                    if not self._enabled(rule):
                        continue
                    line_findings.append(
                        Finding(rule=rule, line=line_no, column=col, char=ch, codepoint=cp, context=path)
                    )
                elif is_noncharacter(cp) or is_private_use(cp):
                    line_findings.append(
                        Finding(
                            rule=NONCHARACTER_RULE,
                            line=line_no,
                            column=col,
                            char=ch,
                            codepoint=cp,
                            context=path,
                        )
                    )

            # Suppression has to be resolved independently of line_findings:
            # a line holding only a confusable pair (IS010) has no per-character
            # findings at all. A cheap substring test keeps the regex off the
            # hot path for every ordinary line.
            suppressed = None
            if "invisiscan:ignore" in line:
                suppressed = self._suppression_for(line)
                if line_findings:
                    line_findings = [f for f in line_findings if f.rule.rule_id not in suppressed]
            result.findings.extend(line_findings)

            if self.detect_confusables and (suppressed is None or "IS010" not in suppressed):
                self._collect_words(line, line_no, path)

        # Confusable groups are deliberately NOT resolved here. The skeleton
        # index accumulates across every scanned file on purpose -- a real
        # homograph attack can pair an identifier in one file with its twin in
        # another -- and they are resolved once, at the end, by
        # distribute_confusables().
        result.sort_findings()
        return result

    # -- confusable index -------------------------------------------------
    def _collect_words(self, line: str, line_no: int, path: str) -> None:
        start = None
        for idx, ch in enumerate(line):
            if ch.isalnum() and (ch.isascii() or is_confusable_candidate(ch)):
                if start is None:
                    start = idx
            else:
                if start is not None:
                    self._index_word(line[start:idx], path, line_no)
                    start = None
        if start is not None:
            self._index_word(line[start:], path, line_no)

    def _index_word(self, word: str, path: str, line_no: int) -> None:
        if len(word) < self.min_word_length:
            return
        skeleton = to_confusable_skeleton(word)
        if not skeleton:
            return
        # Every word is indexed, ASCII ones included: the whole point of a
        # homograph attack is that a non-ASCII clone sits next to the ordinary
        # ASCII identifier it impersonates, so the ASCII variant has to be in
        # the index for the pair ever to be visible.
        entry = self._skeleton_index.setdefault(skeleton, {})
        entry.setdefault(word, set()).add((path, line_no))

    def finalize_confusables(self) -> List[ConfusableGroup]:
        groups: List[ConfusableGroup] = []
        for skeleton, variants in self._skeleton_index.items():
            if len(variants) < 2:
                continue
            # A group only matters if at least one variant is non-ASCII and
            # at least one other differs from it -- i.e. real visual cloning.
            ascii_variants = [w for w in variants if w.isascii()]
            weird_variants = [w for w in variants if not w.isascii()]
            if not weird_variants:
                continue
            if not ascii_variants and len(weird_variants) < 2:
                continue
            group = ConfusableGroup(skeleton=skeleton)
            for word, locs in variants.items():
                for loc in locs:
                    group.add(word, loc)
            groups.append(group)
        groups.sort(key=lambda g: g.skeleton)
        return groups

    def distribute_confusables(self, results: Iterable[ScanResult]) -> int:
        """Attach each resolved group to the file it first appears in.

        Called once after every target has been scanned so a group is reported
        exactly once, while its ``to_dict()`` output still lists every file it
        spans. Returns the number of groups attached.
        """
        by_path = {res.path: res for res in results}
        attached = 0
        for group in self.finalize_confusables():
            # Only files that actually contain a non-ASCII variant are flagged.
            # Files holding merely the plain ASCII twin are useful context --
            # and are still listed in the group's own locations -- but reporting
            # an incident there would be noise.
            flagged_paths = {
                location.rsplit(":", 1)[0]
                for word, locs in group.variants.items()
                if not word.isascii()
                for location in locs
            }
            for path in sorted(flagged_paths):
                target = by_path.get(path)
                if target is None:
                    continue
                if any(g.skeleton == group.skeleton for g in target.confusables):
                    continue
                target.confusables.append(group)
                attached += 1
        for res in results:
            res.confusables.sort(key=lambda g: g.skeleton)
        return attached

    # -- file IO ----------------------------------------------------------
    def scan_file(self, path: Path) -> ScanResult:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            res = ScanResult(path=str(path))
            res.error = "{}: {}".format(type(exc).__name__, exc)
            return res

        # Plain utf-8 decoding keeps a leading BOM as U+FEFF in the text, where
        # rule IS002 reports it at column 1 -- exactly where an editor will take
        # you. (utf-8-sig would strip it and shift every later column.)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            res = ScanResult(path=str(path))
            res.error = "UnicodeDecodeError: {}".format(exc)
            return res
        return self.scan_text(text, str(path))


def iter_targets(
    roots: Sequence[Path],
    extensions: Optional[Set[str]] = None,
    exclude: Sequence[str] = (),
) -> Iterator[Path]:
    """Yield every file under ``roots`` worth scanning."""
    exts = set(extensions) if extensions is not None else set(DEFAULT_EXTENSIONS)
    for root in roots:
        if root.is_file():
            yield root
            continue
        for candidate in sorted(root.rglob("*")):
            if not candidate.is_file():
                continue
            rel = candidate.as_posix()
            if any(pattern in rel for pattern in exclude):
                continue
            if exts and candidate.suffix.lower() not in exts:
                continue
            yield candidate
