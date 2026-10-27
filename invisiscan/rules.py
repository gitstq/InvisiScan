"""Unicode character rules and risk classification for InvisiScan.

All rule tables here are hand-curated from the Unicode Standard chapters
(UAX #9, UAX #15, UAX #31, UTS #39) and the Trojan Source advisories
(CVE-2021-42574 / CVE-2021-42694). No third-party data files required.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, Tuple

# --------------------------------------------------------------------------
# Severity levels
# --------------------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
SEVERITY_NAMES = (CRITICAL, HIGH, MEDIUM, LOW)


@dataclass(frozen=True)
class Rule:
    """A single detection rule.

    Attributes:
        rule_id: Stable machine identifier, e.g. ``IS001``.
        name: Short human name for the category.
        severity: One of CRITICAL / HIGH / MEDIUM / LOW.
        codepoints: Every codepoint governed by this rule.
        reason: Why this character class is dangerous or undesirable.
        remediation: What the user should do when this fires.
    """

    rule_id: str
    name: str
    severity: str
    codepoints: FrozenSet[int]
    reason: str
    remediation: str

    def matches(self, cp: int) -> bool:
        return cp in self.codepoints


def _range(start: int, end: int) -> FrozenSet[int]:
    return frozenset(range(start, end + 1))


def _union(*groups: Iterable[int]) -> FrozenSet[int]:
    merged: set = set()
    for group in groups:
        merged.update(group)
    return frozenset(merged)


# --------------------------------------------------------------------------
# Rule definitions
# --------------------------------------------------------------------------

# IS001 -- Bidirectional controls. These are the core of the Trojan Source
# attack: they reorder how source code renders without changing its parsed
# meaning, so a reviewer sees harmless text while the compiler sees something
# else entirely. Unicode 6.3 deprecated LRE/RLE/LRO/RLO for exactly this
# reason, but they remain legal in every text encoding.
BIDI_CONTROLS: FrozenSet[int] = _union(
    {
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x061C,  # ARABIC LETTER MARK
    }
)

# Pop-formatting characters on their own are far more often legitimate than
# the openers above, so they get their own rule at a lower severity.
BIDI_POP_FORMAT: FrozenSet[int] = _union(
    {
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)

# IS002 -- Zero-width characters. Invisible by definition; commonly used to
# smuggle text past filters, embed watermarks, or build "username\nbypass"
# payloads that look like a single clean word.
ZERO_WIDTH: FrozenSet[int] = _union(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x2060,  # WORD JOINER
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
        0x00AD,  # SOFT HYPHEN
    }
)

# IS003 -- Invisible mathematical operators. Legit inside MathML-heavy text,
# deeply suspicious inside identifiers.
INVISIBLE_OPERATORS: FrozenSet[int] = _union(
    {
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
    }
)

# IS004 -- Unicode tag characters. Every character here renders as nothing
# useful but can encode arbitrary ASCII bytes, which makes them a favourite
# channel for hidden payloads in otherwise-clean-looking strings.
TAG_CHARACTERS: FrozenSet[int] = _range(0xE0000, 0xE007F)

# IS005 -- Bidirectional / attach marks used as weak-signalling steganography.
BIDI_MARKS: FrozenSet[int] = _union(
    {
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
    }
)

# IS006 -- Variation selectors. Needed for correct emoji rendering, but a
# long run of them after a non-emoji base is a classic obfuscation trick.
VARIATION_SELECTORS: FrozenSet[int] = _union(
    _range(0xFE00, 0xFE0F),
    _range(0xE0100, 0xE01EF),
)

# IS007 -- Space look-alikes that break almost every comparison, diff and
# sort assumption developers make about whitespace.
SPACE_LOOKALIKES: FrozenSet[int] = _union(
    {
        0x00A0,  # NO-BREAK SPACE
        0x2028,  # LINE SEPARATOR
        0x2029,  # PARAGRAPH SEPARATOR
        0x202F,  # NARROW NO-BREAK SPACE
        0x205F,  # MEDIUM MATHEMATICAL SPACE
        0x3000,  # IDEOGRAPHIC SPACE
        0x2007,  # FIGURE SPACE
        0x2009,  # THIN SPACE
        0x200A,  # HAIR SPACE
        0x2000,  # EN QUAD
        0x2001,  # EM QUAD
        0x2002,  # EN SPACE
        0x2003,  # EM SPACE
        0x2004,  # THREE-PER-EM SPACE
        0x2005,  # FOUR-PER-EM SPACE
        0x2006,  # SIX-PER-EM SPACE
        0x2008,  # PUNCTUATION SPACE
        0x1680,  # OGHAM SPACE MARK
    }
)

# IS008 -- Deprecated / non-character / unassigned codepoints. Never wanted
# in source control.
DEPRECATED_OR_NONCHARACTER: FrozenSet[int] = _union(
    {0x0340, 0x0341},  # deprecated combining Grave/Acute tone marks
    {0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F},  # deprecated controls
)

RULES: Tuple[Rule, ...] = (
    Rule(
        rule_id="IS001",
        name="bidi-control",
        severity=CRITICAL,
        codepoints=BIDI_CONTROLS,
        reason=(
            "Bidirectional embedding/override/isolate characters can visually "
            "reorder source code or URLs without changing their parsed meaning "
            "(Trojan Source, CVE-2021-42574)."
        ),
        remediation="Remove the character; if bidirectional text is genuinely needed, use markup or isolate it in a dedicated data file.",
    ),
    Rule(
        rule_id="IS002",
        name="zero-width",
        severity=HIGH,
        codepoints=ZERO_WIDTH,
        reason=(
            "Zero-width characters are invisible in most editors and terminals "
            "and are routinely used to hide text, forge identifiers or bypass filters."
        ),
        remediation="Remove the character, or replace it with a visible equivalent such as a regular space.",
    ),
    Rule(
        rule_id="IS003",
        name="invisible-operator",
        severity=HIGH,
        codepoints=INVISIBLE_OPERATORS,
        reason=(
            "Invisible mathematical operators carry semantics but render as "
            "nothing, making expressions impossible to review."
        ),
        remediation="Replace with the visible operator it stands for.",
    ),
    Rule(
        rule_id="IS004",
        name="tag-character",
        severity=CRITICAL,
        codepoints=TAG_CHARACTERS,
        reason=(
            "Unicode tag characters render invisibly but can losslessly encode "
            "arbitrary ASCII payloads inside seemingly clean strings."
        ),
        remediation="Remove all tag characters; they have no legitimate use in source or identifiers.",
    ),
    Rule(
        rule_id="IS005",
        name="bidi-mark",
        severity=MEDIUM,
        codepoints=BIDI_MARKS,
        reason=(
            "LRM/RLM marks are invisible direction hints; a run of them is a "
            "common steganographic channel and they frequently break naive text processing."
        ),
        remediation="Remove unless required for correctness of mixed-direction human-readable text.",
    ),
    Rule(
        rule_id="IS006",
        name="variation-selector",
        severity=LOW,
        codepoints=VARIATION_SELECTORS,
        reason=(
            "Variation selectors alter glyph selection invisibly; long runs or "
            "runs after a non-emoji base usually indicate obfuscation."
        ),
        remediation="Keep only variation selectors that are part of a legitimate emoji sequence.",
    ),
    Rule(
        rule_id="IS007",
        name="space-lookalike",
        severity=MEDIUM,
        codepoints=SPACE_LOOKALIKES,
        reason=(
            "Look-alike spaces break string comparison, diffing, sorting and "
            "most tokenisation logic that assumes ASCII whitespace."
        ),
        remediation="Replace with a normal U+0020 space (or a real newline for U+2028/U+2029).",
    ),
    Rule(
        rule_id="IS008",
        name="deprecated-codepoint",
        severity=LOW,
        codepoints=DEPRECATED_OR_NONCHARACTER,
        reason="Deprecated control characters that Unicode no longer assigns a meaning to.",
        remediation="Remove.",
    ),
    Rule(
        rule_id="IS009",
        name="bidi-pop-format",
        severity=LOW,
        codepoints=BIDI_POP_FORMAT,
        reason=(
            "PDF/PDI terminate a bidirectional run. Harmless in balanced pairs, "
            "but an unbalanced one usually means a striped-out malicious opener."
        ),
        remediation="Remove, or keep only when balanced against a matching isolate/embedding opener.",
    ),
)

RULES_BY_ID: Dict[str, Rule] = {rule.rule_id: rule for rule in RULES}

# IS011 is resolved at scan time rather than from a fixed table: non-characters
# and private-use codepoints are defined by range arithmetic, and enumerating
# them would mean two million pointless set entries.
NONCHARACTER_RULE = Rule(
    rule_id="IS011",
    name="noncharacter",
    severity=MEDIUM,
    codepoints=frozenset(),
    reason="Reserved non-character or private-use codepoint with no defined rendering.",
    remediation="Remove, or replace with a character outside the private-use area.",
)

ALL_RULE_IDS: FrozenSet[str] = frozenset(RULES_BY_ID) | {"IS010", "IS011"}

# Reverse index used by the hot scanning path.
RULE_FOR_CODEPOINT: Dict[int, Rule] = {}
for _rule in RULES:
    for _cp in _rule.codepoints:
        RULE_FOR_CODEPOINT[_cp] = _rule


def is_noncharacter(cp: int) -> bool:
    """True for permanently reserved non-characters (U+FDD0..U+FDEF, xFFFE/xFFFF)."""
    if 0xFDD0 <= cp <= 0xFDEF:
        return True
    return (cp & 0xFFFE) == 0xFFFE


def is_private_use(cp: int) -> bool:
    return 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0xFFFFD or 0x100000 <= cp <= 0x10FFFD
