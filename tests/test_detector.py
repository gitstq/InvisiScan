"""Unit tests for the detection engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from invisiscan.confusables import to_confusable_skeleton
from invisiscan.detector import Scanner
from invisiscan.reporter import render_json, render_sarif, render_text
from invisiscan.rules import CRITICAL, HIGH, LOW, MEDIUM, RULES_BY_ID

FIXTURES = Path(__file__).parent / "fixtures"


def scan(text: str, path: str = "t.py", **kwargs) -> object:
    return Scanner(**kwargs).scan_text(text, path)


def scan_with_confusables(text: str, path: str = "t.py", **kwargs) -> object:
    """scan_text + the one-shot group resolution step.

    Confusable groups are resolved once after every target is scanned (they can
    span files), so single-file callers must ask for that explicitly.
    """
    scanner = Scanner(**kwargs)
    result = scanner.scan_text(text, path)
    scanner.distribute_confusables([result])
    return result


# --------------------------------------------------------------------------
# individual rule coverage
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "char,rule_id",
    [
        ("‏", "IS001"),   # LRM
        ("‎", "IS001"),   # LRM
        ("‮", "IS001"),   # RLO
        ("⁦", "IS001"),   # LRI
        ("⁧", "IS001"),   # RLI
        ("⁨", "IS001"),   # FSI
        ("؜", "IS001"),   # ALM
        ("​", "IS002"),   # ZWSP
        ("‌", "IS002"),   # ZWNJ
        ("‍", "IS002"),   # ZWJ
        ("﻿", "IS002"),   # BOM
        ("⁠", "IS002"),   # word joiner
        ("­", "IS002"),   # soft hyphen
        ("⁡", "IS003"),   # function application
        ("⁢", "IS003"),   # invisible times
        ("⁣", "IS003"),   # invisible separator
        ("⁤", "IS003"),   # invisible plus
        ("\U000e0041", "IS004"),  # tag A
        ("\U000e007f", "IS004"),  # cancel tag
        ("‎", "IS005"),   # LRM (overlaps IS001 set semantics)
        ("︀", "IS006"),   # variation selector
        (" ", "IS007"),   # NBSP
        (" ", "IS007"),   # narrow nbsp
        ("　", "IS007"),   # ideographic space
        (" ", "IS007"),   # line separator
        (" ", "IS007"),   # paragraph separator
        ("̀", "IS008"),   # deprecated combining grave
        ("⁪", "IS008"),   # inhibit symmetric swapping
        ("‬", "IS009"),   # PDF
        ("⁩", "IS009"),   # PDI
    ],
)
def test_every_rule_fires(char, rule_id):
    result = scan("value = '{}'".format(char))
    fired = {f.rule.rule_id for f in result.findings}
    assert rule_id in fired or rule_id.replace("IS001", "IS005") in fired, \
        "expected {} for U+{:04X}, got {}".format(rule_id, ord(char), fired)


def test_rule_catalogue_is_complete():
    assert set(RULES_BY_ID) == {"IS001", "IS002", "IS003", "IS004", "IS005", "IS006", "IS007", "IS008", "IS009"}


def test_no_rule_codepoints_overlap():
    seen = {}
    for rule in RULES_BY_ID.values():
        for cp in rule.codepoints:
            assert cp not in seen, "U+{:04X} claimed by {} and {}".format(cp, seen[cp], rule.rule_id)
            seen[cp] = rule.rule_id


# --------------------------------------------------------------------------
# position accuracy
# --------------------------------------------------------------------------

def test_line_and_column_are_accurate():
    text = "alpha = 1\nbeta = '​'\ngamma = 3\n"
    result = scan(text)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.line == 2
    assert finding.codepoint == 0x200B
    assert ord(text.splitlines()[1][finding.column - 1]) == 0x200B


def test_multiple_findings_on_one_line_keep_order():
    result = scan("a​b‌c‍d")
    assert [f.column for f in result.findings] == [2, 4, 6]
    assert [f.rule.rule_id for f in result.findings] == ["IS002", "IS002", "IS002"]


def test_line_count_recorded():
    result = scan("one\ntwo\nthree\n")
    assert result.lines == 3


# --------------------------------------------------------------------------
# confusables / homographs
# --------------------------------------------------------------------------

def test_cyrillic_homograph_paired_with_ascii():
    result = scan_with_confusables("admin = 1\nаdmin = 2\n")
    assert len(result.confusables) == 1
    group = result.confusables[0]
    assert group.skeleton == "admin"
    assert {"admin", "аdmin"} == set(group.variants)


def test_single_variant_is_not_reported():
    # 'café' collapses onto skeleton 'cafe', but nothing misspells 'cafe'
    # here, so there is no pair worth alarming anyone about.
    result = scan_with_confusables("café = 1\n")
    assert result.confusables == []


def test_shared_skeleton_detection():
    # Cyrillic clones collapse onto their Latin look-alikes...
    assert to_confusable_skeleton("раураӏ") == to_confusable_skeleton("paypal")
    assert to_confusable_skeleton("ѕіzе") == "size"
    assert to_confusable_skeleton("аdmin") == "admin"


def test_distinct_words_keep_distinct_skeletons():
    # ...but words that merely look alike to nobody must stay separate, or the
    # tool would drown users in false pairs.
    assert to_confusable_skeleton("ѕеіzе") == "seize"
    assert to_confusable_skeleton("ѕеіzе") != to_confusable_skeleton("size")
    assert to_confusable_skeleton("alpha") != to_confusable_skeleton("beta")


def test_fullwidth_collapses_in_skeleton():
    assert to_confusable_skeleton("ａｄｍｉｎ") == "admin"


def test_confusables_can_be_disabled():
    scanner = Scanner(detect_confusables=False)
    result = scanner.scan_text("admin = 1\nаdmin = 2\n")
    assert result.confusables == []


def test_min_word_length_filters_short_words():
    text = "管理员a = 1\n"
    scanner = Scanner(min_word_length=5)
    scanner.scan_text(text)
    assert scanner.finalize_confusables() == []


def test_cross_file_group_reported_only_in_offending_file(tmp_path):
    good = tmp_path / "good.py"
    evil = tmp_path / "evil.py"
    good.write_text("admin = 1\n", encoding="utf-8")
    evil.write_text("аdmin = 2\n", encoding="utf-8")

    scanner = Scanner()
    good_result = scanner.scan_file(good)
    evil_result = scanner.scan_file(evil)
    scanner.distribute_confusables([good_result, evil_result])

    # The plain ASCII file is context, not an incident.
    assert good_result.confusables == []
    assert len(evil_result.confusables) == 1
    # ...but the group still records where the ASCII twin lives.
    locations = sorted(evil_result.confusables[0].variants["admin"])
    assert any(str(good) in loc for loc in locations)


# --------------------------------------------------------------------------
# severity filtering
# --------------------------------------------------------------------------

def test_severity_threshold():
    text = "a​b"
    assert len(scan(text, min_severity=LOW).findings) == 1
    assert len(scan(text, min_severity=CRITICAL).findings) == 0


def test_rule_allowlist_and_denylist():
    text = "x​y"
    assert len(scan(text, allow_rules={"IS002"}).findings) == 1
    assert len(scan(text, allow_rules={"IS007"}).findings) == 0
    assert len(scan(text, deny_rules={"IS002"}).findings) == 0


def test_max_severity_reflects_worst_finding():
    result = scan("x​y\n")
    assert result.max_severity() == HIGH


# --------------------------------------------------------------------------
# file handling
# --------------------------------------------------------------------------

def test_missing_file_records_error(tmp_path):
    result = Scanner().scan_file(tmp_path / "nope.py")
    assert result.error is not None
    assert not result.clean


def test_utf8_bom_reported_once(tmp_path):
    target = tmp_path / "bom.py"
    target.write_text("﻿x = 1\n", encoding="utf-8")
    result = Scanner().scan_file(target)
    bom_findings = [f for f in result.findings if f.codepoint == 0xFEFF]
    assert len(bom_findings) == 1
    # Columns after a stripped BOM must stay correct.
    target.write_text("﻿​x\n", encoding="utf-8")
    result = Scanner().scan_file(target)
    assert result.findings[-1].codepoint == 0x200B
    assert result.findings[-1].column == 2


def test_binary_utf16_is_reported_not_crashing(tmp_path):
    target = tmp_path / "u16.txt"
    target.write_bytes("abc".encode("utf-16"))
    result = Scanner().scan_file(target)
    assert result.error is not None


def test_clean_file_is_clean():
    result = scan("def add(a, b):\n    return a + b\n")
    assert result.clean
    assert result.max_severity() is None


def test_real_international_text_has_no_false_positive():
    text = 'title = "café naïve 中文 日本語 한국어 مرحبا"\nemoji = "✅🚀"\n'
    result = scan(text)
    assert result.findings == []
    assert result.confusables == []


# --------------------------------------------------------------------------
# reporters
# --------------------------------------------------------------------------

def test_json_output_shape():
    result = scan("x​y")
    payload = json.loads(render_json([result]))
    assert payload["tool"]["name"] == "invisiscan"
    assert payload["summary"]["findings"] == 1
    assert payload["results"][0]["rule"] == "IS002"
    assert payload["results"][0]["severity"] == HIGH


def test_sarif_output_shape():
    result = scan("x​y")
    payload = json.loads(render_sarif([result]))
    assert payload["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in payload["$schema"]
    driver = payload["runs"][0]["tool"]["driver"]
    assert driver["name"] == "InvisiScan"
    rule_ids = {r["id"] for r in driver["rules"]}
    assert "IS002" in rule_ids
    assert payload["runs"][0]["results"][0]["level"] == "error"


def test_text_report_summarises_severities():
    result = scan("x​y")
    out = render_text([result])
    assert "high: 1" in out
    assert "U+200B" in out


def test_text_report_reports_io_errors(tmp_path):
    result = Scanner().scan_file(tmp_path / "nope.py")
    assert "nope.py" in render_text([result])


def test_emoji_presentation_selectors_are_not_flagged():
    """U+FE0F after an emoji is ordinary presentation, not obfuscation."""
    text = 'msg = "⚠️ error 🔍 found ✅ done 🚀"\n'
    assert scan(text).findings == []


def test_variation_selector_after_non_emoji_is_flagged():
    """The same selector after an ordinary character is still suspicious."""
    result = scan('x = "则︀"\n')
    assert [f.rule.rule_id for f in result.findings] == ["IS006"]
    assert result.findings[0].codepoint == 0xFE00


def test_regional_indicator_and_symbol_singletons_exempt():
    assert scan('flag = "\U0001F1FA\U0001F1F8 ©️ ™️"\n').findings == []


# --------------------------------------------------------------------------
# suppression comments
# --------------------------------------------------------------------------

def test_inline_suppression_silences_named_rule():
    # A zero-width space normally fires, but this line opts out of IS002 only.
    suppressed = scan("token = 'x​y'  # invisiscan:ignore=IS002\n")
    assert suppressed.findings == []


def test_suppression_allows_other_rules_to_still_fire():
    text = "a b  # invisiscan:ignore=IS002\n"
    result = scan(text)
    # NBSP (IS007) is untouched by an IS002-only suppression.
    assert [f.rule.rule_id for f in result.findings] == ["IS007"]


def test_bare_suppression_silences_everything():
    text = "x​ c  # invisiscan:ignore\n"
    assert scan(text).findings == []


def test_suppression_multiple_rules():
    text = "a​ b  # invisiscan:ignore=IS002,IS007\n"
    assert scan(text).findings == []


def test_suppression_is_case_insensitive_and_tolerant():
    text = "a​b  # invisiscan:ignore= is002 \n"
    assert scan(text).findings == []


def test_suppression_applies_only_to_its_own_line():
    text = "ok = 1  # invisiscan:ignore\nbad = 'x​y'\n"
    result = scan(text)
    assert [f.line for f in result.findings] == [2]


def test_suppression_works_for_confusables_without_other_findings():
    """IS010 lines carry no per-character findings, so this guards a real bug."""
    without = scan_with_confusables("admin = 1\nаdmin = 2\n")
    assert len(without.confusables) == 1

    with_ignore = scan_with_confusables("admin = 1  # invisiscan:ignore=IS010\nаdmin = 2\n")
    assert with_ignore.confusables == []


# --------------------------------------------------------------------------
# fixtures round-trip
# --------------------------------------------------------------------------

def test_fixture_files_are_detected():
    scanner = Scanner()
    results = [scanner.scan_file(p) for p in sorted(FIXTURES.glob("*")) if p.is_file()]
    scanner.distribute_confusables(results)
    by_path = {r.path: r for r in results}

    trojan = by_path[[p for p in by_path if p.endswith("trojan_source.py")][0]]
    assert any(f.rule.rule_id == "IS001" for f in trojan.findings)

    tags = by_path[[p for p in by_path if p.endswith("tag_smuggle.txt")][0]]
    assert all(f.rule.rule_id == "IS004" for f in tags.findings)

    clean = by_path[[p for p in by_path if p.endswith("clean.py")][0]]
    assert clean.clean
