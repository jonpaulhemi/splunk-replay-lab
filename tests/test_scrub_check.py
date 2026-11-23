"""The scrub check: deny-listed terms and private IPs are caught; the term itself is never printed."""

import importlib.util
import pathlib

SCRIPT = pathlib.Path(__file__).parents[1] / "tools" / "scrub_check.py"
spec = importlib.util.spec_from_file_location("scrub_check", SCRIPT)
scrub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scrub)


def test_terms_match_case_insensitively_and_skip_comments():
    terms = scrub.parse_terms("# a comment\nSecretHost\n\n  other  \n")
    assert terms == ["secrethost", "other"]
    hits = scrub.scan_text("ok\nssh to SECRETHOST now\n", terms)
    assert hits == [(2, "deny-listed term")]


def test_private_ips_are_caught_public_and_doc_ranges_are_not():
    text = "a 10.1.2.3\nb 172.20.0.1\nc 192.168.0.9\nd 192.0.2.10\ne 8.8.8.8\nf 127.0.0.1\ng 1.2.3.4.5\n"  # scrub: ok
    hits = scrub.scan_text(text, [])
    assert [h[0] for h in hits] == [1, 2, 3]


def test_version_like_numbers_are_not_ips():
    assert scrub.scan_text("version 10.18.300.1000 and 999.1.1.1", []) == []


def test_env_list_wins_over_files(tmp_path):
    listed = tmp_path / "list.txt"
    listed.write_text("fromfile\n")
    terms, source = scrub.load_terms({"SCRUB_DENYLIST": "fromenv", "SCRUB_DENYLIST_FILE": str(listed)},
                                     default_file=tmp_path / "none")
    assert terms == ["fromenv"] and source == "SCRUB_DENYLIST"
    terms, source = scrub.load_terms({"SCRUB_DENYLIST_FILE": str(listed)}, default_file=tmp_path / "none")
    assert terms == ["fromfile"] and source == str(listed)


def test_no_list_reports_none(tmp_path):
    assert scrub.load_terms({}, default_file=tmp_path / "none") == ([], None)


def test_main_never_prints_the_term(tmp_path, monkeypatch, capsys):
    target = tmp_path / "doc.md"
    target.write_text("mentions hiddenname here\n")
    monkeypatch.setenv("SCRUB_DENYLIST", "hiddenname")
    assert scrub.main([str(target)]) == 1
    out = capsys.readouterr().out
    assert "hiddenname" not in out and "doc.md:1" in out


def test_allow_marker_exempts_ips_but_not_terms():
    line = "lab 10.9.9.9 secrethost  # " + "scrub: ok"
    assert scrub.scan_text(line, ["secrethost"]) == [(1, "deny-listed term")]
