"""InvisiScan -- zero-dependency Unicode safety scanner.

Finds the characters that render as nothing or as something else:
invisible zero-width smugglers, Trojan Source bidirectional controls,
hidden tag payloads, look-alike spaces and homograph identifiers.
"""

from .detector import ConfusableGroup, Finding, ScanResult, Scanner, iter_targets
from .reporter import render_json, render_sarif, render_text
from .rules import CRITICAL, HIGH, LOW, MEDIUM, RULES, RULES_BY_ID, SEVERITY_ORDER

__version__ = "1.0.0"
__all__ = [
    "__version__",
    "Scanner",
    "ScanResult",
    "Finding",
    "ConfusableGroup",
    "iter_targets",
    "render_text",
    "render_json",
    "render_sarif",
    "RULES",
    "RULES_BY_ID",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "SEVERITY_ORDER",
]
