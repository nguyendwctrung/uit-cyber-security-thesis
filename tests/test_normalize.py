import json
import sys

from vuln_detection.normalize import main


def test_main_semgrep(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "findings.jsonl"
    error_path = tmp_path / "errors.jsonl"

    data = {
        "results": [{
            "check_id": "java/test-rule",
            "path": "src\\Example.java",
            "start": {"line": 10, "col": 5},
            "end": {"line": 10, "col": 12},
            "extra": {
                "fingerprint": "test-fingerprint",
                "message": "Test message.",
                "severity": "ERROR",
                "metadata": {
                    "cwe": ["CWE-89: SQL Injection"],
                    "vulnerability_class": ["SQL Injection"],
                },
            },
        }],
    }

    input_path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setattr(sys, "argv", [
        "normalize",
        "--scanner", "semgrep",
        "--input", str(input_path),
        "--run-id", "test-run",
        "--raw-artifact", "raw/test.json",
        "--raw-hash", "test-hash",
        "--source-revision", "test-revision",
        "--source-root", "src",
        "--output", str(output_path),
        "--error-output", str(error_path),
    ])

    exit_code = main()
    text = capsys.readouterr().out
    rows = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert exit_code == 0
    assert "Scanner: semgrep" in text
    assert "Findings: 1" in text
    assert len(rows) == 1
    assert rows[0]["scanner"] == "semgrep"
    assert rows[0]["location"]["path"] == "Example.java"
    assert rows[0]["provenance"]["raw_pointer"] == "results[0]"
    assert error_path.read_text(encoding="utf-8") == ""


def test_existing_output_is_not_overwritten(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "findings.jsonl"
    error_path = tmp_path / "errors.jsonl"

    input_path.write_text('{"results": []}', encoding="utf-8")
    output_path.write_text("keep this file\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", [
        "normalize",
        "--scanner", "semgrep",
        "--input", str(input_path),
        "--run-id", "test-run",
        "--raw-artifact", "raw/test.json",
        "--raw-hash", "test-hash",
        "--source-revision", "test-revision",
        "--source-root", "src",
        "--output", str(output_path),
        "--error-output", str(error_path),
    ])

    exit_code = main()
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "Output already exists" in text
    assert output_path.read_text(encoding="utf-8") == "keep this file\n"
    assert not error_path.exists()


def test_unknown_scanner_returns_error(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "findings.jsonl"
    error_path = tmp_path / "errors.jsonl"

    input_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", [
        "normalize",
        "--scanner", "unknown",
        "--input", str(input_path),
        "--run-id", "test-run",
        "--raw-artifact", "raw/test.json",
        "--raw-hash", "test-hash",
        "--source-revision", "test-revision",
        "--source-root", "src",
        "--output", str(output_path),
        "--error-output", str(error_path),
    ])

    exit_code = main()
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "Scanner must be semgrep or codeql." in text
    assert not output_path.exists()
    assert not error_path.exists()