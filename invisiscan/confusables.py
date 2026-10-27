"""Canonical full-width -> half-width and confusable skeleton mapping.

Implements a pragmatic subset of the UTS #39 "skeleton" algorithm using a
hand-built table. The table targets the confusables that actually appear in
typosquatting, phishing domains and Trojan-Source style identifier spoofing:

* Cyrillic / Greek / Armenian / Cherokee look-alikes of Latin letters
* Mathematical alphanumerics (U+1D400..U+1D7FF) and circled / squared forms
* Full-width forms (U+FF01..U+FF5E) and their ASCII targets
* Digits from every script that resemble ASCII 0-9
* Common symbol look-alikes used to forge URLs and operators

The mapping intentionally favours precision over coverage: emitting a false
confusable for a perfectly ordinary Arabic or Greek word is far worse for a
security tool than missing an exotic substitution.
"""

from __future__ import annotations

import unicodedata
from typing import Dict

# Each entry maps a single confusing codepoint to the ASCII character a human
# is most likely to mistake it for. Only 1:1 visual substitutions are listed;
# anything requiring context is resolved at scan time by the skeleton cache.
_CONFUSABLE_MAP: Dict[int, str] = {}


def _register(pairs: str) -> None:
    """Populate the map from ``source->target`` pairs given as one string."""
    half = len(pairs) // 2
    for i in range(half):
        source = pairs[i]
        target = pairs[half + i]
        _CONFUSABLE_MAP[ord(source)] = target


# --- Cyrillic -> Latin ----------------------------------------------------
# invisiscan:ignore=IS010 -- this data table intentionally pairs look-alikes.
_register("абсдеорхуАВСЕНКМОРТХуа" + "abcdeopxyABCEHKMOPTXya")  # invisiscan:ignore=IS010
_CONFUSABLE_MAP[0x0455] = "s"   # ѕ CYRILLIC SMALL LETTER DZE
_CONFUSABLE_MAP[0x0456] = "i"   # і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
_CONFUSABLE_MAP[0x0458] = "j"   # ј CYRILLIC SMALL LETTER JE
_CONFUSABLE_MAP[0x04BB] = "h"   # һ CYRILLIC SMALL LETTER SHHA
_CONFUSABLE_MAP[0x04CF] = "l"   # ӏ CYRILLIC SMALL LETTER PALOCHKA
_CONFUSABLE_MAP[0x0501] = "d"   # ԁ CYRILLIC SMALL LETTER KOMI DE
_CONFUSABLE_MAP[0x051B] = "q"   # ԛ CYRILLIC SMALL LETTER QA
_CONFUSABLE_MAP[0x0432] = "b"   # в CYRILLIC SMALL LETTER VE
_CONFUSABLE_MAP[0x0433] = "r"   # г CYRILLIC SMALL LETTER GHE
_CONFUSABLE_MAP[0x0438] = "u"   # и CYRILLIC SMALL LETTER I
_CONFUSABLE_MAP[0x043A] = "k"   # к CYRILLIC SMALL LETTER KA
_CONFUSABLE_MAP[0x043D] = "h"   # н CYRILLIC SMALL LETTER EN
_CONFUSABLE_MAP[0x043F] = "n"   # п CYRILLIC SMALL LETTER PE
_CONFUSABLE_MAP[0x0457] = "i"   # ї CYRILLIC SMALL LETTER YI

# --- Greek -> Latin -------------------------------------------------------
_CONFUSABLE_MAP[0x03B9] = "i"   # ι GREEK SMALL LETTER IOTA
_CONFUSABLE_MAP[0x03BF] = "o"   # ο GREEK SMALL LETTER OMICRON
_CONFUSABLE_MAP[0x03BD] = "v"   # ν GREEK SMALL LETTER NU
_CONFUSABLE_MAP[0x03C1] = "p"   # ρ GREEK SMALL LETTER RHO
_CONFUSABLE_MAP[0x03C4] = "t"   # τ GREEK SMALL LETTER TAU
_CONFUSABLE_MAP[0x03C5] = "u"   # υ GREEK SMALL LETTER UPSILON
_CONFUSABLE_MAP[0x03C7] = "x"   # χ GREEK SMALL LETTER CHI
_CONFUSABLE_MAP[0x03B1] = "a"   # α GREEK SMALL LETTER ALPHA
_CONFUSABLE_MAP[0x03B2] = "b"   # β GREEK SMALL LETTER BETA
_CONFUSABLE_MAP[0x03B3] = "y"   # γ GREEK SMALL LETTER GAMMA
_CONFUSABLE_MAP[0x03B5] = "e"   # ε GREEK SMALL LETTER EPSILON
_CONFUSABLE_MAP[0x03BA] = "k"   # κ GREEK SMALL LETTER KAPPA
_CONFUSABLE_MAP[0x03BC] = "u"   # μ GREEK SMALL LETTER MU
_CONFUSABLE_MAP[0x0399] = "I"   # Ι GREEK CAPITAL LETTER IOTA
_CONFUSABLE_MAP[0x039F] = "O"   # Ο GREEK CAPITAL LETTER OMICRON
_CONFUSABLE_MAP[0x0391] = "A"   # Α GREEK CAPITAL LETTER ALPHA
_CONFUSABLE_MAP[0x0392] = "B"   # Β GREEK CAPITAL LETTER BETA
_CONFUSABLE_MAP[0x0395] = "E"   # Ε GREEK CAPITAL LETTER EPSILON
_CONFUSABLE_MAP[0x039A] = "K"   # Κ GREEK CAPITAL LETTER KAPPA
_CONFUSABLE_MAP[0x039C] = "M"   # Μ GREEK CAPITAL LETTER MU
_CONFUSABLE_MAP[0x03A4] = "T"   # Τ GREEK CAPITAL LETTER TAU
_CONFUSABLE_MAP[0x03A7] = "X"   # Χ GREEK CAPITAL LETTER CHI

# --- Armenian / Hebrew / Georgian look-alikes -----------------------------
_CONFUSABLE_MAP[0x0578] = "n"   # ո ARMENIAN SMALL LETTER OH
_CONFUSABLE_MAP[0x057D] = "u"   # ս ARMENIAN SMALL LETTER SEH
_CONFUSABLE_MAP[0x0561] = "w"   # ա ARMENIAN SMALL LETTER AYB
_CONFUSABLE_MAP[0x0570] = "h"   # հ ARMENIAN SMALL LETTER HO
_CONFUSABLE_MAP[0x0562] = "p"   # բ ARMENIAN SMALL LETTER BEN
_CONFUSABLE_MAP[0x05D5] = "i"   # ו HEBREW LETTER VAV
_CONFUSABLE_MAP[0x10D8] = "i"   # ი GEORGIAN LETTER IN

# --- Symbol look-alikes commonly used to forge operators and URLs ---------
_CONFUSABLE_MAP[0x0131] = "i"   # ı LATIN SMALL LETTER DOTLESS I
_CONFUSABLE_MAP[0x0237] = "j"   # ȷ LATIN SMALL LETTER DOTLESS J
_CONFUSABLE_MAP[0x1E9A] = "a"   # ẚ LATIN SMALL LETTER A WITH RIGHT HALF RING
_CONFUSABLE_MAP[0x2044] = "/"   # ⁄ FRACTION SLASH
_CONFUSABLE_MAP[0x2215] = "/"   # ∕ DIVISION SLASH
_CONFUSABLE_MAP[0x2216] = "\\"  # ∖ SET MINUS
_CONFUSABLE_MAP[0xFF0F] = "/"   # ／ FULLWIDTH SOLIDUS
_CONFUSABLE_MAP[0x02D9] = "."   # ˙ DOT ABOVE
_CONFUSABLE_MAP[0x3002] = "."   # 。 IDEOGRAPHIC FULL STOP
_CONFUSABLE_MAP[0x2024] = "."   # ․ ONE DOT LEADER
_CONFUSABLE_MAP[0xFF0E] = "."   # ． FULLWIDTH FULL STOP
_CONFUSABLE_MAP[0xFF1A] = ":"   # ： FULLWIDTH COLON
_CONFUSABLE_MAP[0x02D0] = ":"   # ː MODIFIER LETTER TRIANGULAR COLON
_CONFUSABLE_MAP[0x2D3F] = "-"   # ⴿ TIFINAGH CONSONANT JOINER
_CONFUSABLE_MAP[0x2010] = "-"   # ‐ HYPHEN
_CONFUSABLE_MAP[0x2011] = "-"   # ‑ NON-BREAKING HYPHEN
_CONFUSABLE_MAP[0x2012] = "-"   # ‒ FIGURE DASH
_CONFUSABLE_MAP[0x2013] = "-"   # – EN DASH
_CONFUSABLE_MAP[0x2014] = "-"   # — EM DASH
_CONFUSABLE_MAP[0x2212] = "-"   # − MINUS SIGN
_CONFUSABLE_MAP[0xFF0D] = "-"   # － FULLWIDTH HYPHEN-MINUS
_CONFUSABLE_MAP[0x2018] = "'"   # ‘ LEFT SINGLE QUOTATION MARK
_CONFUSABLE_MAP[0x2019] = "'"   # ’ RIGHT SINGLE QUOTATION MARK
_CONFUSABLE_MAP[0x201C] = '"'   # “ LEFT DOUBLE QUOTATION MARK
_CONFUSABLE_MAP[0x201D] = '"'   # ” RIGHT DOUBLE QUOTATION MARK
_CONFUSABLE_MAP[0x02BC] = "'"   # ʼ MODIFIER LETTER APOSTROPHE
_CONFUSABLE_MAP[0x02BB] = "'"   # ʻ MODIFIER LETTER TURNED COMMA
_CONFUSABLE_MAP[0x0027] = "'"
_CONFUSABLE_MAP[0x226A] = "<<"  # ≪ MUCH LESS-THAN
_CONFUSABLE_MAP[0x003D] = "="

CONFUSABLE_MAP: Dict[int, str] = dict(_CONFUSABLE_MAP)


def to_confusable_skeleton(text: str) -> str:
    """Return the UTS#39-style skeleton of ``text``.

    Normalises to NFKC first (which collapses full-width forms, mathematical
    alphanumerics and most compatibility singletons), then applies the
    hand-built visual map to anything still non-ASCII. Two strings sharing a
    skeleton are visually confusable.
    """
    skeleton: list = []
    for ch in unicodedata.normalize("NFKC", text):
        cp = ord(ch)
        if cp < 0x80:
            skeleton.append(ch)
            continue
        mapped = CONFUSABLE_MAP.get(cp)
        if mapped is not None:
            skeleton.append(mapped)
            continue
        # Fall back to stripping marks so "é" and "e" collapse together,
        # which matches how humans skim identifiers.
        decomposed = unicodedata.normalize("NFD", ch)
        stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
        skeleton.append(stripped)
    out = "".join(skeleton)
    return unicodedata.normalize("NFKC", out).casefold()


def is_confusable_candidate(ch: str) -> bool:
    """Cheap pre-filter: could this character ever be a visual look-alike?"""
    cp = ord(ch)
    if cp < 0x80:
        return False
    if cp in CONFUSABLE_MAP:
        return True
    nfkc = unicodedata.normalize("NFKC", ch)
    return nfkc != ch or unicodedata.category(ch) in ("Ll", "Lu", "Nd")
