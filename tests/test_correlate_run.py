import json
import sys

from vuln_detection.correlate_run import main


def make_finding(scanner, finding_id):
    return {
        "finding_id": finding_id,
        "scanner": scanner,
        "location": {
            "path": "src/Example.java",
            "start_line": 10,
        },
        "cwe_ids": ["CWE-22"],
        "provenance": {
            "raw_pointer": scanner + "-pointer",
        },
    }


def write_rows(path, rows):
    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row))
            file.write("\n")


def test_main_writes_candidates(tmp_path, monkeypatch, capsys):
    semgrep_path = tmp_path / "semgrep.jsonl"
    codeql_path = tmp_path / "codeql.jsonl"
    output_path = tmp_path / "candidates.jsonl"

    write_rows(semgrep_path, [make_finding("semgrep", "semgrep-1")])
    write_rows(codeql_path, [make_finding("codeql", "codeql-1")])

    monkeypatch.setattr(sys, "argv", [
        "correlate_run",
        "--semgrep-input", str(semgrep_path),
        "--codeql-input", str(codeql_path),
        "--output", str(output_path),
    ])

    exit_code = main()
    text = capsys.readouterr().out
    rows = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert exit_code == 0
    assert "Candidates: 1" in text
    assert len(rows) == 1
    assert rows[0]["match_rule"] == "path-line-cwe-v1"
    assert rows[0]["member_ids"] == ["codeql-1", "semgrep-1"]


def test_existing_output_is_not_overwritten(tmp_path, monkeypatch, capsys):
    semgrep_path = tmp_path / "semgrep.jsonl"
    codeql_path = tmp_path / "codeql.jsonl"
    output_path = tmp_path / "candidates.jsonl"

    write_rows(semgrep_path, [make_finding("semgrep", "semgrep-1")])
    write_rows(codeql_path, [make_finding("codeql", "codeql-1")])
    output_path.write_text("keep this file\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", [
        "correlate_run",
        "--semgrep-input", str(semgrep_path),
        "--codeql-input", str(codeql_path),
        "--output", str(output_path),
    ])

    exit_code = main()
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "Output already exists" in text
    assert output_path.read_text(encoding="utf-8") == "keep this file\n"


def test_invalid_input_returns_error(tmp_path, monkeypatch, capsys):
    semgrep_path = tmp_path / "semgrep.jsonl"
    codeql_path = tmp_path / "codeql.jsonl"
    output_path = tmp_path / "candidates.jsonl"

    semgrep_path.write_text("not json\n", encoding="utf-8")
    write_rows(codeql_path, [make_finding("codeql", "codeql-1")])

    monkeypatch.setattr(sys, "argv", [
        "correlate_run",
        "--semgrep-input", str(semgrep_path),
        "--codeql-input", str(codeql_path),
        "--output", str(output_path),
    ])

    exit_code = main()
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "Correlation failed:" in text
    assert not output_path.exists()